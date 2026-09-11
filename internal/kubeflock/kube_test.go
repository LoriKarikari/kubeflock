package kubeflock

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
	sandboxapi "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsfake "sigs.k8s.io/agent-sandbox/clients/k8s/extensions/clientset/versioned/fake"
	extensionsapi "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
)

func TestJSONPatchOperationEncoding(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation jsonPatchOperation
		want      string
	}{
		{"uid", jsonPatchOperation{Op: "test", Path: "/metadata/uid", Value: types.UID("uid")}, `{"op":"test","path":"/metadata/uid","value":"uid"}`},
		{"empty resource version", jsonPatchOperation{Op: "test", Path: "/metadata/resourceVersion", Value: ""}, `{"op":"test","path":"/metadata/resourceVersion","value":""}`},
		{"mode", jsonPatchOperation{Op: "add", Path: "/spec/operatingMode", Value: modeSuspended}, `{"op":"add","path":"/spec/operatingMode","value":"Suspended"}`},
		{"labels", jsonPatchOperation{Op: "add", Path: "/metadata/labels", Value: map[string]string{sandboxapi.SandboxAdoptableLabel: "true"}}, `{"op":"add","path":"/metadata/labels","value":{"agents.x-k8s.io/adoptable":"true"}}`},
		{"remove", jsonPatchOperation{Op: "remove", Path: "/metadata/labels/agents.x-k8s.io~1adoptable"}, `{"op":"remove","path":"/metadata/labels/agents.x-k8s.io~1adoptable"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.operation)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != test.want {
				t.Fatalf("patch = %s, want %s", data, test.want)
			}
		})
	}
}

func TestClaimResponsesRequireIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*extensionsapi.SandboxClaim)
	}{
		{"missing name", func(claim *extensionsapi.SandboxClaim) { claim.Name = "" }},
		{"missing UID", func(claim *extensionsapi.SandboxClaim) { claim.UID = "" }},
		{"missing warm pool", func(claim *extensionsapi.SandboxClaim) { claim.Spec.WarmPoolRef.Name = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := claimFixture("named", "dev-pool")
			test.mutate(&claim)
			clientset := extensionsfake.NewSimpleClientset()
			clientset.PrependReactor("*", "sandboxclaims", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, claim.DeepCopy(), nil
			})
			client := kubeClient{extensions: clientset.ExtensionsV1beta1()}
			if _, err := client.getClaim(t.Context(), "dev", "named"); err == nil || !strings.Contains(err.Error(), "invalid SandboxClaim") {
				t.Fatalf("lookup with incomplete identity = %v", err)
			}
			if _, err := client.createClaim(t.Context(), KubeTarget{Namespace: "dev"}, "named", "dev-pool", nil); err == nil || !strings.Contains(err.Error(), "invalid SandboxClaim") {
				t.Fatalf("creation with incomplete identity = %v", err)
			}
		})
	}
}

func TestCreateClaimPreservesIdentityAndHomeOverride(t *testing.T) {
	clientset := extensionsfake.NewSimpleClientset()
	clientset.PrependReactor("create", "sandboxclaims", func(action ktesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(ktesting.CreateActionImpl)
		if !ok {
			t.Fatalf("unexpected create action %T", action)
		}
		options := create.GetCreateOptions()
		if options.FieldManager != "kubeflock" || options.FieldValidation != "Strict" {
			t.Errorf("claim create options = %#v", options)
		}
		claim, ok := create.GetObject().(*extensionsapi.SandboxClaim)
		if !ok {
			t.Fatalf("unexpected create object %T", create.GetObject())
		}
		claim.UID = types.UID("claim-" + claim.Name)
		return false, nil, nil
	})
	client := kubeClient{extensions: clientset.ExtensionsV1beta1()}
	template := gateTemplate()
	template.Spec.VolumeClaimTemplates[0].Labels = map[string]string{"template-label": "value"}
	template.Spec.VolumeClaimTemplates[0].Annotations = map[string]string{"template-annotation": "value"}
	approved, err := validateTemplate(template, "dev-pool")
	if err != nil {
		t.Fatal(err)
	}
	home := approved.Home
	claim, err := client.createClaim(context.Background(), KubeTarget{Namespace: "dev"}, "named", "dev-pool", &home)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Name != "named" || claim.Namespace != "dev" || claim.Labels[managedByLabel] != managedByValue {
		t.Fatalf("claim identity = %s/%s labels %v", claim.Namespace, claim.Name, claim.Labels)
	}
	if claim.Spec.WarmPoolRef.Name != "dev-pool" || len(claim.Spec.VolumeClaimTemplates) != 1 {
		t.Fatalf("claim spec = %#v", claim.Spec)
	}
	override := claim.Spec.VolumeClaimTemplates[0]
	if override.Name != home.Name || override.Spec.StorageClassName == nil || *override.Spec.StorageClassName != "longhorn" || override.Spec.Resources.Requests.Storage().Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("home override = %#v", override)
	}
	if len(override.Labels) != 0 || len(override.Annotations) != 0 {
		t.Fatalf("home override copied template metadata: %#v", override)
	}
	claim, err = client.createClaim(context.Background(), KubeTarget{Namespace: "dev"}, "without-home", "dev-pool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(claim.Spec.VolumeClaimTemplates) != 0 {
		t.Fatalf("unexpected home override: %#v", claim.Spec.VolumeClaimTemplates)
	}
}

func gateTemplate() extensionsapi.SandboxTemplate {
	container := corev1.Container{
		Name:  "agent",
		Image: "sandbox:1",
		Ports: []corev1.ContainerPort{{Name: "ssh", ContainerPort: 2222}},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			RunAsNonRoot:             new(true),
			RunAsUser:                new(int64(1000)),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "home", MountPath: "/home/agent"}},
	}
	template := extensionsapi.SandboxTemplate{Name: "dev-small"}
	template.Spec.NetworkPolicyManagement = "Managed"
	template.Spec.PodTemplate.Spec = corev1.PodSpec{
		RuntimeClassName:             new("gvisor"),
		AutomountServiceAccountToken: new(false),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   new(true),
			RunAsUser:      new(int64(1000)),
			RunAsGroup:     new(int64(1000)),
			FSGroup:        new(int64(1000)),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{container},
		Volumes: []corev1.Volume{{
			Name:                  "home",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "home"},
		}},
	}
	template.Spec.VolumeClaimTemplates = []sandboxapi.PersistentVolumeClaimTemplate{{
		Name: "home",
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: new("longhorn"),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			},
		},
	}}
	return template
}

func hardenedInitContainer() corev1.Container {
	container := gateTemplate().Spec.PodTemplate.Spec.Containers[0]
	container.Name, container.Ports, container.VolumeMounts = "setup", nil, nil
	return container
}

func TestValidateTemplateHardeningGate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*extensionsapi.SandboxTemplate)
		want   string
	}{
		{name: "hardened template", mutate: func(*extensionsapi.SandboxTemplate) {}},
		{name: "home without a storage request", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests = nil
		}, want: "must expose a valid SSH port and mount a persistent home at /home/agent"},
		{name: "home with a zero storage request", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("0")
		}, want: "must expose a valid SSH port and mount a persistent home at /home/agent"},
		{name: "hardened init container", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{hardenedInitContainer()}
		}},
		{name: "unmanaged network policy", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.NetworkPolicyManagement = "Unmanaged"
		}, want: "pod hardening requirements"},
		{name: "privileged container", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Privileged = new(true)
		}, want: "unhardened or unbudgeted container agent"},
		{name: "privileged init container", mutate: func(template *extensionsapi.SandboxTemplate) {
			container := hardenedInitContainer()
			container.SecurityContext.Privileged = new(true)
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{container}
		}, want: "unhardened or unbudgeted container setup"},
		{name: "init container without security context", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "evil:1"}}
		}, want: "unhardened or unbudgeted container setup"},
		{name: "added capability", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		}, want: "unhardened or unbudgeted container agent"},
		{name: "unmasked proc mount", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.ProcMount = new(corev1.UnmaskedProcMount)
		}, want: "unhardened or unbudgeted container agent"},
		{name: "host network", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostNetwork = true
		}, want: "pod hardening requirements"},
		{name: "host pid", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostPID = true
		}, want: "pod hardening requirements"},
		{name: "host ipc", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostIPC = true
		}, want: "pod hardening requirements"},
		{name: "shared process namespace", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.ShareProcessNamespace = new(true)
		}, want: "pod hardening requirements"},
		{name: "host path volume", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:     "node",
				HostPath: &corev1.HostPathVolumeSource{Path: "/"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "secret volume", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:   "token",
				Secret: &corev1.SecretVolumeSource{SecretName: "other"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "undeclared claim volume", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:                  "other",
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "other"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "ephemeral container", mutate: func(template *extensionsapi.SandboxTemplate) {
			template.Spec.PodTemplate.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
				Name: "debug", Image: "evil:1",
			}}
		}, want: "declares ephemeral containers"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template := gateTemplate()
			test.mutate(&template)
			_, err := validateTemplate(template, "dev-small-pool")
			if test.want == "" {
				if err != nil {
					t.Fatalf("validateTemplate rejected a hardened template: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateTemplate error = %v, want %q", err, test.want)
			}
		})
	}
}
