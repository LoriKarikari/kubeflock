package kubeflock

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func gateTemplate() sandboxTemplate {
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
	template := sandboxTemplate{}
	template.Metadata = metav1.ObjectMeta{Name: "dev-small"}
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
	template.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{
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
		mutate func(*sandboxTemplate)
		want   string
	}{
		{name: "hardened template", mutate: func(*sandboxTemplate) {}},
		{name: "home without a storage request", mutate: func(template *sandboxTemplate) {
			template.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests = nil
		}, want: "must expose a valid SSH port and mount a persistent home at /home/agent"},
		{name: "home with a zero storage request", mutate: func(template *sandboxTemplate) {
			template.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("0")
		}, want: "must expose a valid SSH port and mount a persistent home at /home/agent"},
		{name: "hardened init container", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{hardenedInitContainer()}
		}},
		{name: "unmanaged network policy", mutate: func(template *sandboxTemplate) {
			template.Spec.NetworkPolicyManagement = "Unmanaged"
		}, want: "pod hardening requirements"},
		{name: "privileged container", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Privileged = new(true)
		}, want: "unhardened or unbudgeted container agent"},
		{name: "privileged init container", mutate: func(template *sandboxTemplate) {
			container := hardenedInitContainer()
			container.SecurityContext.Privileged = new(true)
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{container}
		}, want: "unhardened or unbudgeted container setup"},
		{name: "init container without security context", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "evil:1"}}
		}, want: "unhardened or unbudgeted container setup"},
		{name: "added capability", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		}, want: "unhardened or unbudgeted container agent"},
		{name: "unmasked proc mount", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Containers[0].SecurityContext.ProcMount = ptr.To(corev1.UnmaskedProcMount)
		}, want: "unhardened or unbudgeted container agent"},
		{name: "host network", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostNetwork = true
		}, want: "pod hardening requirements"},
		{name: "host pid", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostPID = true
		}, want: "pod hardening requirements"},
		{name: "host ipc", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.HostIPC = true
		}, want: "pod hardening requirements"},
		{name: "shared process namespace", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.ShareProcessNamespace = new(true)
		}, want: "pod hardening requirements"},
		{name: "host path volume", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:     "node",
				HostPath: &corev1.HostPathVolumeSource{Path: "/"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "secret volume", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:   "token",
				Secret: &corev1.SecretVolumeSource{SecretName: "other"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "undeclared claim volume", mutate: func(template *sandboxTemplate) {
			template.Spec.PodTemplate.Spec.Volumes = append(template.Spec.PodTemplate.Spec.Volumes, corev1.Volume{
				Name:                  "other",
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "other"},
			})
		}, want: "mounts a volume that is not one of its claim templates"},
		{name: "ephemeral container", mutate: func(template *sandboxTemplate) {
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
