package kubeflock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	extensionsapi "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
)

func TestPrepareCreationSerializesSameSandbox(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "id")
	if err := os.WriteFile(identity, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := KubeTarget{Context: "homelab", Namespace: "developer"}
	options := createOptions{Template: "dev-small", IdentityFile: identity, Global: globalOptions{StateDir: dir}}
	_, first, err := prepareCreation(target, "sandbox", options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareCreation(target, "sandbox", options); err == nil || !strings.Contains(err.Error(), "storage operation in progress") {
		t.Fatalf("concurrent creation was not rejected: %v", err)
	}
	if err := first.Unlock(); err != nil {
		t.Fatal(err)
	}
	if _, retry, err := prepareCreation(target, "sandbox", options); err != nil {
		t.Fatalf("retry did not acquire the allocation lock: %v", err)
	} else if err := retry.Unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestProgressSurfacesQuotaExhaustion(t *testing.T) {
	claim := extensionsapi.SandboxClaim{}
	claim.Status.Conditions = []metav1.Condition{{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  "ReconcilerError",
		Message: "pod is forbidden: exceeded quota",
	}}
	got := progress(claim)
	if got.State != "failed" || !strings.Contains(got.Message, "quota") {
		t.Fatalf("quota progress = %#v", got)
	}
}

func TestSandboxStatusReportsStoppedSandbox(t *testing.T) {
	saved := ManagedSandbox{
		Version:      1,
		Phase:        managedBound,
		Name:         "sandbox",
		Claim:        SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox", UID: "claim-uid"},
		Template:     "dev-small",
		WarmPool:     "dev-small",
		IdentityFile: "/key",
		Sandbox:      &SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox", UID: "sandbox-uid"},
		Home:         &PersistentHome{Name: "home-sandbox", UID: "home-uid", Capacity: "10Gi", StorageClass: "longhorn"},
	}
	claim := extensionsapi.SandboxClaim{Name: "sandbox", UID: "claim-uid"}
	claim.Status.SandboxStatus.Name = "sandbox"
	claim.Status.Conditions = []metav1.Condition{{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  "SandboxSuspended",
		Message: "Sandbox is suspended",
	}}

	stopped := sandboxStatus(saved, []extensionsapi.SandboxClaim{claim}, nil, nil, map[string]bool{"sandbox-uid": true})
	if stopped.State != "disconnected" || !strings.Contains(stopped.Message, "kubeflock sandbox resume sandbox") {
		t.Fatalf("stopped status = %#v", stopped)
	}
	running := sandboxStatus(saved, []extensionsapi.SandboxClaim{claim}, nil, nil, nil)
	if running.State != "provisioning" {
		t.Fatalf("unsuspended status = %#v", running)
	}
}

func TestStorageLockSerializesRestoreAndDeletion(t *testing.T) {
	target := KubeTarget{Context: "homelab", Namespace: "developer"}
	dir := t.TempDir()
	first, err := acquireSandboxLock(target, "sandbox", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Unlock() }()
	if _, err := acquireSandboxLock(target, "sandbox", dir); err == nil {
		t.Fatal("concurrent storage operation acquired the same lock")
	}
}
