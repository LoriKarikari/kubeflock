package kubeflock

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

var (
	sandboxResource  = schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}
	claimResource    = schema.GroupVersionResource{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxclaims"}
	templateResource = schema.GroupVersionResource{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxtemplates"}
	poolResource     = schema.GroupVersionResource{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxwarmpools"}
)

type kubeClient struct {
	dynamic dynamic.Interface
	core    coreclient.CoreV1Interface
}

type condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type sandboxClaim struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		WarmPoolRef struct {
			Name string `json:"name"`
		} `json:"warmPoolRef"`
	} `json:"spec"`
	Status struct {
		Conditions []condition `json:"conditions"`
		Sandbox    struct {
			Name string `json:"name"`
		} `json:"sandbox"`
	} `json:"status"`
}

type sandboxObject struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Status   struct {
		Selector   string      `json:"selector"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type sandboxTemplate struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		NetworkPolicyManagement string                         `json:"networkPolicyManagement"`
		PodTemplate             corev1.PodTemplateSpec         `json:"podTemplate"`
		VolumeClaimTemplates    []corev1.PersistentVolumeClaim `json:"volumeClaimTemplates"`
	} `json:"spec"`
}

type sandboxPool struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		Replicas           *int32 `json:"replicas"`
		SandboxTemplateRef struct {
			Name string `json:"name"`
		} `json:"sandboxTemplateRef"`
	} `json:"spec"`
}

type approvedTemplate struct {
	Name, WarmPool, HomeTemplate string
}

type resolvedSandbox struct {
	Identity       SandboxIdentity
	Pod, Container string
	SSHPort        int32
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
		timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		env := make([]string, 0, len(auth.Exec.Env))
		for _, item := range auth.Exec.Env {
			env = append(env, item.Name+"="+item.Value)
		}
		output, err := runCaptured(timeoutCtx, auth.Exec.Command, auth.Exec.Args, env, nil)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig credential helper failed: %s", commandDetail(err))
		}
		var credential struct {
			Status struct {
				Token, ClientCertificateData, ClientKeyData string
			} `json:"status"`
		}
		if json.Unmarshal([]byte(output), &credential) != nil {
			return nil, errors.New("kubeconfig credential helper returned an invalid ExecCredential")
		}
		status := credential.Status
		if status.Token == "" && (status.ClientCertificateData == "" || status.ClientKeyData == "") {
			return nil, errors.New("kubeconfig credential helper returned no usable credentials")
		}
		auth.Exec = nil
		execToken = status.Token
		if status.ClientCertificateData != "" {
			execCert, err = base64.StdEncoding.DecodeString(status.ClientCertificateData)
			if err != nil {
				return nil, errors.New("kubeconfig credential helper returned invalid certificate data")
			}
			execKey, err = base64.StdEncoding.DecodeString(status.ClientKeyData)
			if err != nil {
				return nil, errors.New("kubeconfig credential helper returned invalid key data")
			}
		}
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
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	coreClient, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &kubeClient{dynamic: dynamicClient, core: coreClient}, nil
}

func (k *kubeClient) getClaim(ctx context.Context, namespace, name string) (*sandboxClaim, error) {
	list, err := k.dynamic.Resource(claimResource).Namespace(namespace).List(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + name})
	if err != nil {
		return nil, err
	}
	if len(list.Items) > 1 {
		return nil, fmt.Errorf("multiple SandboxClaims named %s", name)
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	var claim sandboxClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[0].Object, &claim); err != nil {
		return nil, err
	}
	if claim.Metadata.Name == "" || claim.Metadata.UID == "" || claim.Spec.WarmPoolRef.Name == "" {
		return nil, errors.New("invalid SandboxClaim returned by Kubernetes")
	}
	return &claim, nil
}

func (k *kubeClient) createClaim(ctx context.Context, target KubeTarget, name, warmPool string) (*sandboxClaim, error) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
		"metadata": map[string]any{"name": name, "namespace": target.Namespace, "labels": map[string]any{managedByLabel: managedByValue}},
		"spec":     map[string]any{"warmPoolRef": map[string]any{"name": warmPool}},
	}}
	created, err := k.dynamic.Resource(claimResource).Namespace(target.Namespace).Create(ctx, object, metav1.CreateOptions{FieldManager: "kubeflock", FieldValidation: "Strict"})
	if err != nil {
		return nil, err
	}
	var claim sandboxClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(created.Object, &claim); err != nil {
		return nil, err
	}
	return &claim, nil
}

func (k *kubeClient) listClaims(ctx context.Context, namespace string) ([]sandboxClaim, error) {
	list, err := k.dynamic.Resource(claimResource).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: managedByLabel + "=" + managedByValue})
	if err != nil {
		return nil, err
	}
	claims := make([]sandboxClaim, len(list.Items))
	for i := range list.Items {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[i].Object, &claims[i]); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func (k *kubeClient) resolveApprovedTemplate(ctx context.Context, namespace, name string) (approvedTemplate, error) {
	object, err := k.dynamic.Resource(templateResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return approvedTemplate{}, err
	}
	var template sandboxTemplate
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &template); err != nil {
		return approvedTemplate{}, err
	}
	pools, err := k.dynamic.Resource(poolResource).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return approvedTemplate{}, err
	}
	var matches []sandboxPool
	for _, item := range pools.Items {
		var pool sandboxPool
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &pool); err != nil {
			return approvedTemplate{}, err
		}
		if pool.Spec.SandboxTemplateRef.Name == name {
			matches = append(matches, pool)
		}
	}
	if len(matches) != 1 {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s must have exactly one SandboxWarmPool; found %d", name, len(matches))
	}
	if matches[0].Spec.Replicas == nil || *matches[0].Spec.Replicas != 0 {
		return approvedTemplate{}, fmt.Errorf("SandboxWarmPool %s must have zero warm standbys for cold creation", matches[0].Metadata.Name)
	}
	return validateTemplate(template, matches[0].Metadata.Name)
}

func validateTemplate(template sandboxTemplate, warmPool string) (approvedTemplate, error) {
	name := template.Metadata.Name
	if name == "" || template.Spec.NetworkPolicyManagement == "Unmanaged" || !podHardened(template.Spec.PodTemplate.Spec) {
		return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s does not meet Kubeflock pod hardening requirements", name)
	}
	for _, container := range template.Spec.PodTemplate.Spec.Containers {
		if !containerHardened(container) {
			return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s contains an unhardened or unbudgeted container", name)
		}
	}
	if home, ok := homeClaimTemplate(template); ok {
		return approvedTemplate{Name: name, WarmPool: warmPool, HomeTemplate: home.Name}, nil
	}
	return approvedTemplate{}, fmt.Errorf("SandboxTemplate %s must expose a valid SSH port and mount a persistent home at /home/agent", name)
}

func podHardened(pod corev1.PodSpec) bool {
	security := pod.SecurityContext
	return ptr.Deref(pod.RuntimeClassName, "") == "gvisor" &&
		!ptr.Deref(pod.AutomountServiceAccountToken, true) &&
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
		!ptr.Deref(security.AllowPrivilegeEscalation, true) &&
		ptr.Deref(security.RunAsNonRoot, false) &&
		ptr.Deref(security.RunAsUser, 0) == 1000 &&
		security.SeccompProfile != nil &&
		security.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault &&
		security.Capabilities != nil &&
		slices.Contains(security.Capabilities.Drop, corev1.Capability("ALL")) &&
		len(container.Resources.Requests) != 0 &&
		len(container.Resources.Limits) != 0
}

func homeClaimTemplate(template sandboxTemplate) (corev1.PersistentVolumeClaim, bool) {
	pod := template.Spec.PodTemplate.Spec
	for _, container := range pod.Containers {
		if findSSHPort(container.Ports) == 0 {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/home/agent" {
				continue
			}
			claimName := ""
			for _, volume := range pod.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil {
					claimName = volume.PersistentVolumeClaim.ClaimName
				}
			}
			for _, home := range template.Spec.VolumeClaimTemplates {
				capacity := home.Spec.Resources.Requests.Storage()
				if home.Name == claimName && home.Spec.StorageClassName != nil && capacity != nil {
					return home, true
				}
			}
		}
	}
	return corev1.PersistentVolumeClaim{}, false
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

func (k *kubeClient) resolveSandbox(ctx context.Context, target KubeTarget, name, expectedUID string) (resolvedSandbox, error) {
	object, err := k.dynamic.Resource(sandboxResource).Namespace(target.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return resolvedSandbox{}, err
	}
	var sandbox sandboxObject
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &sandbox); err != nil {
		return resolvedSandbox{}, err
	}
	if expectedUID != "" && string(sandbox.Metadata.UID) != expectedUID {
		return resolvedSandbox{}, fmt.Errorf("sandbox %s/%s was replaced: expected UID %s, found %s", target.Namespace, name, expectedUID, sandbox.Metadata.UID)
	}
	ready := false
	for _, condition := range sandbox.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			ready = true
		}
	}
	if !ready {
		return resolvedSandbox{}, fmt.Errorf("sandbox %s/%s is not ready", target.Namespace, name)
	}
	pods, err := k.core.Pods(target.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sandbox.Status.Selector})
	if err != nil {
		return resolvedSandbox{}, err
	}
	owned := make([]corev1.Pod, 0, 1)
	for _, pod := range pods.Items {
		for _, owner := range pod.OwnerReferences {
			if owner.Controller != nil && *owner.Controller && owner.UID == sandbox.Metadata.UID {
				owned = append(owned, pod)
				break
			}
		}
	}
	if len(owned) != 1 {
		return resolvedSandbox{}, fmt.Errorf("sandbox %s/%s owns %d matching pods; expected exactly one", target.Namespace, name, len(owned))
	}
	pod := owned[0]
	container := pod.Annotations["kubectl.kubernetes.io/default-container"]
	if container == "" && len(pod.Spec.Containers) == 1 {
		container = pod.Spec.Containers[0].Name
	}
	var port int32
	found := false
	for _, candidate := range pod.Spec.Containers {
		if candidate.Name != container {
			continue
		}
		found = true
		port = findSSHPort(candidate.Ports)
	}
	if !found {
		return resolvedSandbox{}, fmt.Errorf("pod %s/%s has no unambiguous default container", target.Namespace, pod.Name)
	}
	if port < 1 || port > 65535 {
		return resolvedSandbox{}, fmt.Errorf("pod %s/%s has no valid SSH port", target.Namespace, pod.Name)
	}
	return resolvedSandbox{Identity: SandboxIdentity{Context: target.Context, Namespace: sandbox.Metadata.Namespace, Name: sandbox.Metadata.Name, UID: string(sandbox.Metadata.UID)}, Pod: pod.Name, Container: container, SSHPort: port}, nil
}

func (k *kubeClient) resolveHome(ctx context.Context, target KubeTarget, sandbox SandboxIdentity, homeTemplate string) (PersistentHome, error) {
	pvc, err := k.core.PersistentVolumeClaims(target.Namespace).Get(ctx, homeTemplate+"-"+sandbox.Name, metav1.GetOptions{})
	if err != nil {
		return PersistentHome{}, err
	}
	owned := false
	for _, owner := range pvc.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && string(owner.UID) == sandbox.UID {
			owned = true
		}
	}
	if !owned {
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

func commandDetail(err error) string {
	var command *commandError
	if errors.As(err, &command) {
		return cmp.Or(strings.TrimSpace(command.Stderr), strings.TrimSpace(command.Stdout), err.Error())
	}
	return err.Error()
}
