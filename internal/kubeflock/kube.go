package kubeflock

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
	sandboxapi "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxclient "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/typed/api/v1beta1"
	extensionsclient "sigs.k8s.io/agent-sandbox/clients/k8s/extensions/clientset/versioned/typed/api/v1beta1"
	extensionsapi "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
)

const sandboxNameHashLabel = "agents.x-k8s.io/sandbox-name-hash"

type kubeClient struct {
	sandboxes  sandboxclient.AgentsV1beta1Interface
	extensions extensionsclient.ExtensionsV1beta1Interface
	core       coreclient.CoreV1Interface
}

type jsonPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitzero"`
}

type approvedTemplate struct {
	Name            string
	WarmPool        string
	Image           string
	ResourceVersion string
	Home            sandboxapi.PersistentVolumeClaimTemplate
	HomeOverrides   bool
}

type resolvedSandbox struct {
	Identity  SandboxIdentity
	Pod       string
	Container string
	SSHPort   int32
}

func newKubeClient(ctx context.Context, target KubeTarget, kubeconfig string) (*kubeClient, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	raw, err := rules.Load()
	if err != nil {
		return nil, err
	}
	contextConfig, ok := raw.Contexts[target.Context]
	if !ok {
		return nil, fmt.Errorf("context %q not found in kubeconfig", target.Context)
	}
	var execToken string
	var execCert, execKey []byte
	if auth := raw.AuthInfos[contextConfig.AuthInfo]; auth != nil && auth.Exec != nil {
		execToken, execCert, execKey, err = runExecCredential(ctx, auth.Exec, raw.Clusters[contextConfig.Cluster])
		if err != nil {
			return nil, err
		}
		// ponytail: the helper runs once per command and the token never refreshes, so a
		// credential shorter-lived than a wait window fails mid-command. Refresh on 401 if it bites.
		auth.Exec = nil
	}
	config, err := clientcmd.NewNonInteractiveClientConfig(*raw, target.Context, &clientcmd.ConfigOverrides{}, rules).ClientConfig()
	if err != nil {
		return nil, err
	}
	if execToken != "" {
		config.BearerToken = execToken
	}
	if len(execCert) != 0 {
		config.CertData, config.KeyData = execCert, execKey
	}
	sandboxClient, err := sandboxclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	extensionsClient, err := extensionsclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	coreClient, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &kubeClient{sandboxes: sandboxClient, extensions: extensionsClient, core: coreClient}, nil
}

type execCredentialInfo struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Spec       execCredentialInfoSpec `json:"spec"`
}

type execCredentialInfoSpec struct {
	Interactive bool                   `json:"interactive"`
	Cluster     *execCredentialCluster `json:"cluster,omitempty"`
}

type execCredentialCluster struct {
	Server                   string `json:"server,omitempty"`
	TLSServerName            string `json:"tls-server-name,omitempty"`
	InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthorityData string `json:"certificate-authority-data,omitempty"`
	ProxyURL                 string `json:"proxy-url,omitempty"`
}

func runExecCredential(ctx context.Context, execConfig *clientcmdapi.ExecConfig, cluster *clientcmdapi.Cluster) (string, []byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if execConfig.InteractiveMode == clientcmdapi.AlwaysExecInteractiveMode {
		return "", nil, nil, fmt.Errorf("kubeconfig credential helper %s requires an interactive session", execConfig.Command)
	}
	info, err := execCredentialInfoFor(execConfig, cluster)
	if err != nil {
		return "", nil, nil, err
	}
	env := make([]string, 0, len(execConfig.Env)+1)
	for _, item := range execConfig.Env {
		env = append(env, item.Name+"="+item.Value)
	}
	env = append(env, "KUBERNETES_EXEC_INFO="+string(info))
	output, err := runCaptured(ctx, execConfig.Command, execConfig.Args, env, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("kubeconfig credential helper: %w", err)
	}
	var credential struct {
		Status struct {
			Token                 string `json:"token"`
			ClientCertificateData string `json:"clientCertificateData"`
			ClientKeyData         string `json:"clientKeyData"`
		} `json:"status"`
	}
	if json.Unmarshal([]byte(output), &credential) != nil {
		return "", nil, nil, errors.New("kubeconfig credential helper returned an invalid ExecCredential")
	}
	status := credential.Status
	if status.Token == "" && (status.ClientCertificateData == "" || status.ClientKeyData == "") {
		return "", nil, nil, errors.New("kubeconfig credential helper returned no usable credentials")
	}
	if status.ClientCertificateData == "" {
		return status.Token, nil, nil, nil
	}
	cert, err := base64.StdEncoding.DecodeString(status.ClientCertificateData)
	if err != nil {
		return "", nil, nil, errors.New("kubeconfig credential helper returned invalid certificate data")
	}
	key, err := base64.StdEncoding.DecodeString(status.ClientKeyData)
	if err != nil {
		return "", nil, nil, errors.New("kubeconfig credential helper returned invalid key data")
	}
	return status.Token, cert, key, nil
}

// execCredentialInfoFor builds the KUBERNETES_EXEC_INFO payload that the credential plugin
// contract requires, including the cluster details clients must pass on request.
func execCredentialInfoFor(execConfig *clientcmdapi.ExecConfig, cluster *clientcmdapi.Cluster) ([]byte, error) {
	apiVersion := execConfig.APIVersion
	switch apiVersion {
	case "":
		apiVersion = "client.authentication.k8s.io/v1beta1"
	case "client.authentication.k8s.io/v1beta1", "client.authentication.k8s.io/v1":
	default:
		return nil, fmt.Errorf("unsupported kubeconfig credential helper apiVersion %q", apiVersion)
	}
	info := execCredentialInfo{APIVersion: apiVersion, Kind: "ExecCredential", Spec: execCredentialInfoSpec{Interactive: false}}
	if execConfig.ProvideClusterInfo && cluster != nil {
		info.Spec.Cluster = &execCredentialCluster{
			Server:                   cluster.Server,
			TLSServerName:            cluster.TLSServerName,
			InsecureSkipTLSVerify:    cluster.InsecureSkipTLSVerify,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(cluster.CertificateAuthorityData),
			ProxyURL:                 cluster.ProxyURL,
		}
	}
	return json.Marshal(info)
}

func (k *kubeClient) getClaim(ctx context.Context, namespace, name string) (*extensionsapi.SandboxClaim, error) {
	claim, err := k.extensions.SandboxClaims(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateClaimIdentity(claim); err != nil {
		return nil, err
	}
	return claim, nil
}

func validateClaimIdentity(claim *extensionsapi.SandboxClaim) error {
	if claim.Name == "" || claim.UID == "" || claim.Spec.WarmPoolRef.Name == "" {
		return errors.New("invalid SandboxClaim returned by Kubernetes")
	}
	return nil
}

func (k *kubeClient) createClaim(ctx context.Context, target KubeTarget, name, warmPool string, home *sandboxapi.PersistentVolumeClaimTemplate) (*extensionsapi.SandboxClaim, error) {
	claim := &extensionsapi.SandboxClaim{
		Name: name, Namespace: target.Namespace, Labels: map[string]string{managedByLabel: managedByValue},
		Spec: extensionsapi.SandboxClaimSpec{WarmPoolRef: extensionsapi.SandboxWarmPoolRef{Name: warmPool}},
	}
	if home != nil {
		claim.Spec.VolumeClaimTemplates = []sandboxapi.PersistentVolumeClaimTemplate{*home}
	}
	created, err := k.extensions.SandboxClaims(target.Namespace).Create(ctx, claim, metav1.CreateOptions{FieldManager: "kubeflock", FieldValidation: "Strict"})
	if err != nil {
		return nil, err
	}
	if err := validateClaimIdentity(created); err != nil {
		return nil, err
	}
	return created, nil
}

func (k *kubeClient) resolveApprovedTemplate(ctx context.Context, namespace, name string) (approvedTemplate, error) {
	template, err := k.extensions.SandboxTemplates(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return approvedTemplate{}, err
	}
	pools, err := k.extensions.SandboxWarmPools(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return approvedTemplate{}, err
	}
	var matches []extensionsapi.SandboxWarmPool
	for _, pool := range pools.Items {
		if pool.Spec.TemplateRef.Name == name {
			matches = append(matches, pool)
		}
	}
	if len(matches) != 1 {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s must have exactly one SandboxWarmPool; found %d", name, len(matches))
	}
	if matches[0].Spec.Replicas == nil {
		return approvedTemplate{}, fmt.Errorf("SandboxWarmPool %s has no replica count", matches[0].Name)
	}
	return validateTemplate(*template, matches[0].Name)
}

func validateTemplate(template extensionsapi.SandboxTemplate, warmPool string) (approvedTemplate, error) {
	name := template.Name
	pod := template.Spec.PodTemplate.Spec
	if name == "" || template.Spec.NetworkPolicyManagement == extensionsapi.NetworkPolicyManagementUnmanaged || !podHardened(pod) {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s does not meet Kubeflock pod hardening requirements", name)
	}
	if len(pod.EphemeralContainers) != 0 {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s declares ephemeral containers", name)
	}
	for _, container := range slices.Concat(pod.InitContainers, pod.Containers) {
		if !containerHardened(container) {
			return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s contains an unhardened or unbudgeted container %s", name, container.Name)
		}
	}
	if !volumesHardened(pod.Volumes, template.Spec.VolumeClaimTemplates) {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s mounts a volume that is not one of its claim templates", name)
	}
	if home, image, ok := homeClaimTemplate(template); ok {
		return approvedTemplate{Name: name, WarmPool: warmPool, Image: image, ResourceVersion: template.ResourceVersion, Home: home, HomeOverrides: template.Spec.VolumeClaimTemplatesPolicy == extensionsapi.VolumeClaimTemplatesPolicyOverrides}, nil
	}
	return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s must expose a valid SSH port and mount a persistent home at /home/agent", name)
}

func podHardened(pod corev1.PodSpec) bool {
	security := pod.SecurityContext
	return ptr.Deref(pod.RuntimeClassName, "") == "gvisor" &&
		!ptr.Deref(pod.AutomountServiceAccountToken, true) &&
		!pod.HostNetwork &&
		!pod.HostPID &&
		!pod.HostIPC &&
		!ptr.Deref(pod.ShareProcessNamespace, false) &&
		security != nil &&
		ptr.Deref(security.RunAsNonRoot, false) &&
		ptr.Deref(security.RunAsUser, 0) == 1000 &&
		ptr.Deref(security.RunAsGroup, 0) == 1000 &&
		ptr.Deref(security.FSGroup, 0) == 1000 &&
		security.SeccompProfile != nil &&
		security.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault
}

func containerHardened(container corev1.Container) bool {
	security := container.SecurityContext
	return security != nil &&
		!ptr.Deref(security.Privileged, false) &&
		security.ProcMount == nil &&
		!ptr.Deref(security.AllowPrivilegeEscalation, true) &&
		ptr.Deref(security.RunAsNonRoot, false) &&
		ptr.Deref(security.RunAsUser, 0) == 1000 &&
		security.SeccompProfile != nil &&
		security.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault &&
		security.Capabilities != nil &&
		len(security.Capabilities.Add) == 0 &&
		slices.Contains(security.Capabilities.Drop, corev1.Capability("ALL")) &&
		len(container.Resources.Requests) != 0 &&
		len(container.Resources.Limits) != 0
}

func volumesHardened(volumes []corev1.Volume, templates []sandboxapi.PersistentVolumeClaimTemplate) bool {
	claims := make([]string, 0, len(templates))
	for _, template := range templates {
		claims = append(claims, template.Name)
	}
	for _, volume := range volumes {
		if volume.PersistentVolumeClaim == nil || !slices.Contains(claims, volume.PersistentVolumeClaim.ClaimName) {
			return false
		}
	}
	return true
}

func homeClaimTemplate(template extensionsapi.SandboxTemplate) (sandboxapi.PersistentVolumeClaimTemplate, string, bool) {
	pod := template.Spec.PodTemplate.Spec
	for _, container := range pod.Containers {
		if findSSHPort(container.Ports) == 0 {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/home/agent" {
				continue
			}
			claimName := mountedClaimName(pod.Volumes, mount.Name)
			if home, ok := validHomeTemplate(template.Spec.VolumeClaimTemplates, claimName); ok {
				return home, container.Image, true
			}
		}
	}
	return sandboxapi.PersistentVolumeClaimTemplate{}, "", false
}

func mountedClaimName(volumes []corev1.Volume, mountName string) string {
	for _, volume := range volumes {
		if volume.Name == mountName && volume.PersistentVolumeClaim != nil {
			return volume.PersistentVolumeClaim.ClaimName
		}
	}
	return ""
}

func validHomeTemplate(templates []sandboxapi.PersistentVolumeClaimTemplate, claimName string) (sandboxapi.PersistentVolumeClaimTemplate, bool) {
	for _, home := range templates {
		if home.Name == claimName && home.Spec.StorageClassName != nil && !home.Spec.Resources.Requests.Storage().IsZero() {
			return sandboxapi.PersistentVolumeClaimTemplate{Name: home.Name, Spec: home.Spec}, true
		}
	}
	return sandboxapi.PersistentVolumeClaimTemplate{}, false
}

func controlledBy(owners []metav1.OwnerReference, uid types.UID) bool {
	return slices.ContainsFunc(owners, func(owner metav1.OwnerReference) bool {
		return ptr.Deref(owner.Controller, false) && owner.UID == uid
	})
}

func foreignOwner(owners []metav1.OwnerReference, allowed types.UID) (metav1.OwnerReference, bool) {
	if len(owners) == 0 {
		return metav1.OwnerReference{}, false
	}
	if allowed != "" && len(owners) == 1 && controlledBy(owners, allowed) {
		return metav1.OwnerReference{}, false
	}
	return owners[0], true
}

func findSSHPort(ports []corev1.ContainerPort) int32 {
	for _, port := range ports {
		if port.Name == "ssh" && port.ContainerPort > 0 && port.ContainerPort <= 65535 {
			return port.ContainerPort
		}
	}
	for _, port := range ports {
		if port.ContainerPort == 2222 {
			return port.ContainerPort
		}
	}
	return 0
}

func (k *kubeClient) getSandbox(ctx context.Context, target KubeTarget, name, expectedUID string) (*sandboxapi.Sandbox, error) {
	sandbox, err := k.getSandboxIfExists(ctx, target, name, expectedUID)
	if err != nil {
		return nil, err
	}
	if sandbox == nil {
		return nil, fmt.Errorf("sandbox %s/%s is missing", target.Namespace, name)
	}
	return sandbox, nil
}

func (k *kubeClient) getSandboxIfExists(ctx context.Context, target KubeTarget, name, expectedUID string) (*sandboxapi.Sandbox, error) {
	sandbox, err := k.sandboxes.Sandboxes(target.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expectedUID != "" && string(sandbox.UID) != expectedUID {
		return nil, fmt.Errorf("sandbox %s/%s was replaced: expected UID %s, found %s", target.Namespace, name, expectedUID, sandbox.UID)
	}
	return sandbox, nil
}

func (k *kubeClient) setOperatingMode(ctx context.Context, target KubeTarget, sandbox *sandboxapi.Sandbox, mode sandboxOperatingMode) error {
	if cmp.Or(sandbox.Spec.OperatingMode, modeRunning) == mode {
		return nil
	}
	patch, err := json.Marshal([]jsonPatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: sandbox.UID},
		{Op: "test", Path: "/metadata/resourceVersion", Value: sandbox.ResourceVersion},
		{Op: "add", Path: "/spec/operatingMode", Value: mode},
	})
	if err != nil {
		return err
	}
	_, err = k.sandboxes.Sandboxes(target.Namespace).Patch(
		ctx,
		sandbox.Name,
		types.JSONPatchType,
		patch,
		metav1.PatchOptions{FieldManager: "kubeflock", FieldValidation: "Strict"},
	)
	return err
}

func (k *kubeClient) ownedPods(ctx context.Context, target KubeTarget, sandbox *sandboxapi.Sandbox) ([]corev1.Pod, error) {
	if sandbox.Status.LabelSelector == "" {
		return nil, fmt.Errorf("sandbox %s/%s returned no pod selector", target.Namespace, sandbox.Name)
	}
	pods, err := k.core.Pods(target.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sandbox.Status.LabelSelector})
	if err != nil {
		return nil, err
	}
	var owned []corev1.Pod
	for _, pod := range pods.Items {
		if controlledBy(pod.OwnerReferences, sandbox.UID) {
			owned = append(owned, pod)
		}
	}
	return owned, nil
}

func (k *kubeClient) homePVC(ctx context.Context, target KubeTarget, expected PersistentHome) (*corev1.PersistentVolumeClaim, error) {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if string(pvc.UID) != expected.UID {
		return nil, fmt.Errorf("sandbox home %s was replaced", expected.Name)
	}
	return pvc, nil
}

func (k *kubeClient) ownedHome(ctx context.Context, target KubeTarget, sandbox SandboxIdentity, expected PersistentHome) (*corev1.PersistentVolumeClaim, error) {
	pvc, err := k.homePVC(ctx, target, expected)
	if err != nil {
		return nil, err
	}
	if !controlledBy(pvc.OwnerReferences, types.UID(sandbox.UID)) {
		return nil, fmt.Errorf("sandbox home %s was replaced", expected.Name)
	}
	return pvc, nil
}

func (k *kubeClient) verifyRestorableHome(ctx context.Context, target KubeTarget, name string, expected PersistentHome, template sandboxapi.PersistentVolumeClaimTemplate, allowedSandboxUID string) error {
	pvc, err := k.homePVC(ctx, target, expected)
	if err != nil {
		return err
	}
	if expected.Name != template.Name+"-"+name {
		return fmt.Errorf("retained home %s does not match template claim name %s", pvc.Name, template.Name)
	}
	if pvc.Spec.StorageClassName == nil || template.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != *template.Spec.StorageClassName {
		return fmt.Errorf("retained home %s uses storage class %q, not template storage class %q", pvc.Name, ptr.Deref(pvc.Spec.StorageClassName, ""), ptr.Deref(template.Spec.StorageClassName, ""))
	}
	requested := template.Spec.Resources.Requests[corev1.ResourceStorage]
	capacity := pvc.Status.Capacity[corev1.ResourceStorage]
	if requested.IsZero() || capacity.IsZero() || capacity.Cmp(requested) < 0 {
		return fmt.Errorf("retained home %s capacity %s is incompatible with template request %s", pvc.Name, capacity.String(), requested.String())
	}
	for _, mode := range template.Spec.AccessModes {
		if !slices.Contains(pvc.Spec.AccessModes, mode) {
			return fmt.Errorf("retained home %s does not support template access mode %s", pvc.Name, mode)
		}
	}
	if ptr.Deref(pvc.Spec.VolumeMode, corev1.PersistentVolumeFilesystem) != ptr.Deref(template.Spec.VolumeMode, corev1.PersistentVolumeFilesystem) {
		return fmt.Errorf("retained home %s has an incompatible volume mode", pvc.Name)
	}
	if owner, conflict := foreignOwner(pvc.OwnerReferences, types.UID(allowedSandboxUID)); conflict {
		return fmt.Errorf("retained home %s is owned by %s/%s", pvc.Name, owner.Kind, owner.Name)
	}
	pods, err := k.core.Pods(target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvc.Name && (allowedSandboxUID == "" || !controlledBy(pod.OwnerReferences, types.UID(allowedSandboxUID))) {
				return fmt.Errorf("retained home %s is mounted by Pod %s", pvc.Name, pod.Name)
			}
		}
	}
	return nil
}

func (k *kubeClient) authorizeHomeAdoption(ctx context.Context, target KubeTarget, expected PersistentHome, allowedSandboxUID string) error {
	pvc, err := k.homePVC(ctx, target, expected)
	if err != nil {
		return err
	}
	if owner, conflict := foreignOwner(pvc.OwnerReferences, types.UID(allowedSandboxUID)); conflict {
		return fmt.Errorf("retained home %s became owned by %s/%s before allocation", pvc.Name, owner.Kind, owner.Name)
	}
	patch := []jsonPatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: pvc.UID},
		{Op: "test", Path: "/metadata/resourceVersion", Value: pvc.ResourceVersion},
	}
	if pvc.Labels == nil {
		patch = append(patch, jsonPatchOperation{Op: "add", Path: "/metadata/labels", Value: map[string]string{sandboxapi.SandboxAdoptableLabel: "true"}})
	} else if pvc.Labels[sandboxapi.SandboxAdoptableLabel] != "true" {
		patch = append(patch, jsonPatchOperation{Op: "add", Path: "/metadata/labels/agents.x-k8s.io~1adoptable", Value: "true"})
	}
	if len(patch) == 2 {
		return nil
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = k.core.PersistentVolumeClaims(target.Namespace).Patch(ctx, pvc.Name, types.JSONPatchType, data, metav1.PatchOptions{})
	return err
}

func (k *kubeClient) preventHomeReAdoption(ctx context.Context, target KubeTarget, sandbox SandboxIdentity, expected PersistentHome) error {
	pvc, err := k.ownedHome(ctx, target, sandbox, expected)
	if err != nil {
		return err
	}
	patch := []jsonPatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: pvc.UID},
		{Op: "test", Path: "/metadata/resourceVersion", Value: pvc.ResourceVersion},
	}
	for _, label := range []string{sandboxNameHashLabel, sandboxapi.SandboxAdoptableLabel} {
		if _, exists := pvc.Labels[label]; exists {
			patch = append(patch, jsonPatchOperation{Op: "remove", Path: "/metadata/labels/" + strings.ReplaceAll(label, "/", "~1")})
		}
	}
	if len(patch) == 2 {
		return nil
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = k.core.PersistentVolumeClaims(target.Namespace).Patch(ctx, pvc.Name, types.JSONPatchType, data, metav1.PatchOptions{})
	return err
}

func (k *kubeClient) verifyRetainedHome(ctx context.Context, target KubeTarget, sandbox SandboxIdentity, expected PersistentHome) error {
	pvc, err := k.homePVC(ctx, target, expected)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("sandbox home %s is missing from the cluster; no retained home was recorded", expected.Name)
	}
	if err != nil {
		return err
	}
	if slices.ContainsFunc(pvc.OwnerReferences, func(owner metav1.OwnerReference) bool { return owner.UID == types.UID(sandbox.UID) }) {
		return fmt.Errorf("sandbox home %s is still owned by Sandbox UID %s", expected.Name, sandbox.UID)
	}
	return nil
}

func (k *kubeClient) inspectHomeDeletion(ctx context.Context, target KubeTarget, retained RetainedHome) (*PersistentVolume, error) {
	pvc, err := k.homePVC(ctx, target, retained.Home)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("retained home %s PVC is already gone from the cluster; the storage changed outside Kubeflock", retained.Home.Name)
	}
	if err != nil {
		return nil, err
	}
	if len(pvc.OwnerReferences) != 0 || pvc.Labels[sandboxapi.SandboxAdoptableLabel] == "true" {
		return nil, fmt.Errorf("retained home %s has uncertain ownership or is reserved for restore", pvc.Name)
	}
	claim, err := k.getClaim(ctx, target.Namespace, retained.claimIdentity().Name)
	if err != nil {
		return nil, err
	}
	sandbox, err := k.getSandboxIfExists(ctx, target, retained.Origin.Name, "")
	if err != nil {
		return nil, err
	}
	if claim != nil || sandbox != nil {
		return nil, fmt.Errorf("retained home %s has an active or uncertain sandbox allocation", pvc.Name)
	}
	pods, err := k.core.Pods(target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, pod := range pods.Items {
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvc.Name {
				return nil, fmt.Errorf("retained home %s is mounted by Pod %s", pvc.Name, pod.Name)
			}
		}
	}
	if pvc.Spec.VolumeName == "" {
		return nil, fmt.Errorf("retained home %s has no bound persistent volume", pvc.Name)
	}
	volume, err := k.core.PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	claimRef := volume.Spec.ClaimRef
	if claimRef == nil || claimRef.Namespace != target.Namespace || claimRef.Name != pvc.Name || claimRef.UID != pvc.UID {
		return nil, fmt.Errorf("persistent volume %s has uncertain ownership", volume.Name)
	}
	return &PersistentVolume{Name: volume.Name, UID: string(volume.UID), ReclaimPolicy: string(volume.Spec.PersistentVolumeReclaimPolicy)}, nil
}

func (k *kubeClient) verifyPendingHomeDeletion(ctx context.Context, target KubeTarget, retained RetainedHome) error {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, retained.Home.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) || (err == nil && string(pvc.UID) != retained.Home.UID) {
		return nil
	}
	if err != nil {
		return err
	}
	volume, err := k.inspectHomeDeletion(ctx, target, retained)
	if err != nil {
		return err
	}
	if volume != nil && (retained.Deletion == nil || *volume != *retained.Deletion) {
		return errors.New("retained home storage identity changed during deletion")
	}
	return nil
}

func (k *kubeClient) deleteHomePVC(ctx context.Context, target KubeTarget, expected PersistentHome) error {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(pvc.UID) != expected.UID {
		return nil
	}
	uid := pvc.UID
	err = k.core.PersistentVolumeClaims(target.Namespace).Delete(ctx, pvc.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (k *kubeClient) homeDeletionComplete(ctx context.Context, target KubeTarget, home PersistentHome, volume *PersistentVolume) (bool, error) {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, home.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	if err == nil && string(pvc.UID) == home.UID {
		return false, nil
	}
	if volume == nil {
		return true, nil
	}
	pv, err := k.core.PersistentVolumes().Get(ctx, volume.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if string(pv.UID) != volume.UID {
		return true, nil
	}
	return false, nil
}

func (k *kubeClient) orphanDeleteClaim(ctx context.Context, target KubeTarget, identity SandboxIdentity) error {
	uid := types.UID(identity.UID)
	policy := metav1.DeletePropagationOrphan
	err := k.extensions.SandboxClaims(target.Namespace).Delete(ctx, identity.Name, metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: &uid},
		PropagationPolicy: &policy,
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (k *kubeClient) orphanDeleteSandbox(ctx context.Context, target KubeTarget, identity SandboxIdentity) error {
	uid := types.UID(identity.UID)
	policy := metav1.DeletePropagationOrphan
	err := k.sandboxes.Sandboxes(target.Namespace).Delete(ctx, identity.Name, metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: &uid},
		PropagationPolicy: &policy,
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (k *kubeClient) suspendedSandboxes(ctx context.Context, target KubeTarget, managed []ManagedSandbox) (map[string]bool, error) {
	suspended := map[string]bool{}
	for _, saved := range managed {
		if saved.Sandbox == nil {
			continue
		}
		sandbox, err := k.getSandboxIfExists(ctx, target, saved.Sandbox.Name, "")
		if err != nil {
			return nil, err
		}
		if sandbox == nil || string(sandbox.UID) != saved.Sandbox.UID {
			continue
		}
		if sandbox.Spec.OperatingMode == modeSuspended {
			suspended[saved.Sandbox.UID] = true
		}
	}
	return suspended, nil
}

func (k *kubeClient) resolveSandbox(ctx context.Context, target KubeTarget, name, expectedUID string) (resolvedSandbox, error) {
	sandbox, err := k.getSandbox(ctx, target, name, expectedUID)
	if err != nil {
		return resolvedSandbox{}, err
	}
	if !meta.IsStatusConditionTrue(sandbox.Status.Conditions, "Ready") {
		return resolvedSandbox{}, fmt.Errorf("sandbox %s/%s is not ready", target.Namespace, name)
	}
	owned, err := k.ownedPods(ctx, target, sandbox)
	if err != nil {
		return resolvedSandbox{}, err
	}
	if len(owned) != 1 {
		return resolvedSandbox{}, fmt.Errorf("sandbox %s/%s owns %d matching pods; expected exactly one", target.Namespace, name, len(owned))
	}
	pod := owned[0]
	container := pod.Annotations["kubectl.kubernetes.io/default-container"]
	if container == "" && len(pod.Spec.Containers) == 1 {
		container = pod.Spec.Containers[0].Name
	}
	index := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == container })
	if index < 0 {
		return resolvedSandbox{}, fmt.Errorf("pod %s/%s has no unambiguous default container", target.Namespace, pod.Name)
	}
	port := findSSHPort(pod.Spec.Containers[index].Ports)
	if port < 1 || port > 65535 {
		return resolvedSandbox{}, fmt.Errorf("pod %s/%s has no valid SSH port", target.Namespace, pod.Name)
	}
	return resolvedSandbox{
		Identity: SandboxIdentity{
			Context:   target.Context,
			Namespace: sandbox.Namespace,
			Name:      sandbox.Name,
			UID:       string(sandbox.UID),
		},
		Pod:       pod.Name,
		Container: container,
		SSHPort:   port,
	}, nil
}

func (k *kubeClient) resolveHome(ctx context.Context, target KubeTarget, sandbox SandboxIdentity, homeTemplate string) (PersistentHome, error) {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, homeTemplate+"-"+sandbox.Name, metav1.GetOptions{})
	if err != nil {
		return PersistentHome{}, err
	}
	if !controlledBy(pvc.OwnerReferences, types.UID(sandbox.UID)) {
		return PersistentHome{}, fmt.Errorf("PersistentVolumeClaim %s is not owned by Sandbox UID %s", pvc.Name, sandbox.UID)
	}
	capacity := "unknown"
	if value, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
		capacity = value.String()
	}
	storageClass := ""
	if pvc.Spec.StorageClassName != nil {
		storageClass = *pvc.Spec.StorageClassName
	}
	return PersistentHome{Name: pvc.Name, UID: string(pvc.UID), Capacity: capacity, StorageClass: storageClass}, nil
}
