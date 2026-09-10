package kubeflock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
