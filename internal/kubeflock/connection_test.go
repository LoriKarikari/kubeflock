package kubeflock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testConnection(stateDir, configFile string) Connection {
	sshDir := filepath.Join(filepath.Dir(stateDir), "ssh")
	return Connection{
		Version: 1,
		Phase:   "prepared",
		Sandbox: SandboxIdentity{Context: "test", Namespace: "dev", Name: "sandbox", UID: "sandbox-uid"},
		SSH: SSHState{
			Alias:          "kubeflock-sandbox-uid",
			IdentityFile:   filepath.Join(stateDir, "..", "id_ed25519"),
			KnownHostsFile: filepath.Join(sshDir, "sandbox-uid.known_hosts"),
			EntryFile:      filepath.Join(sshDir, "sandbox-uid.conf"),
			ProxyFile:      filepath.Join(sshDir, "sandbox-uid-proxy"),
			ConfigFile:     configFile,
			HostKey:        testHostKey,
		},
		Herdr: HerdrState{Label: "sandbox", Session: "agent"},
	}
}

func TestEnsureSSHFilesFollowsSymlinkedConfig(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	target := filepath.Join(dir, "dotfiles", "config")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("Host unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "sshconfig")
	if err := os.Symlink(target, configFile); err != nil {
		t.Fatal(err)
	}
	connection := testConnection(stateDir, configFile)
	if err := ensureSSHFiles(connection, filepath.Join(stateDir, "sandbox-uid.json")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("ssh config symlink was replaced by a regular file")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "Include ") || !strings.Contains(string(data), "Host unrelated") {
		t.Fatalf("symlink target was not updated in place: %q", data)
	}
}

func TestValidateSSHStateRejectsControlCharacters(t *testing.T) {
	clean := testConnection(filepath.Join(t.TempDir(), "state"), filepath.Join(t.TempDir(), "sshconfig"))
	if err := validateSSHState(clean.SSH); err != nil {
		t.Fatalf("rejected a valid SSH state: %v", err)
	}
	hostile := clean.SSH
	hostile.IdentityFile = "/home/agent/id_ed25519\nHost evil.example.com"
	if err := validateSSHState(hostile); err == nil {
		t.Fatal("accepted a newline in the identity file path")
	}
}

func TestAdoptIdentityOnlyBeforeConnection(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "id_first")
	second := filepath.Join(dir, "id_second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("private key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resolvedFirst, err := resolveIdentityFile(first)
	if err != nil {
		t.Fatal(err)
	}
	resolvedSecond, err := resolveIdentityFile(second)
	if err != nil {
		t.Fatal(err)
	}
	saved := savedConnection{File: filepath.Join(dir, "sandbox-uid.json"), Connection: testConnection(dir, filepath.Join(dir, "sshconfig"))}
	saved.Connection.SSH.IdentityFile = resolvedFirst

	if err := validateSavedConnection(&saved, connectOptions{IdentityFile: second}); err != nil {
		t.Fatalf("prepared connection rejected a corrected identity: %v", err)
	}
	if saved.Connection.SSH.IdentityFile != resolvedSecond {
		t.Fatalf("identity = %q; want %q", saved.Connection.SSH.IdentityFile, resolvedSecond)
	}

	saved.Connection.Phase = connectionConnected
	if err := validateSavedConnection(&saved, connectOptions{IdentityFile: first}); err == nil {
		t.Fatal("connected connection switched identity")
	}
}

func TestDisconnectScopesToTarget(t *testing.T) {
	dir := t.TempDir()
	for _, sandbox := range []SandboxIdentity{
		{Context: "homelab", Namespace: "dev", Name: "sandbox", UID: "uid-homelab"},
		{Context: "other", Namespace: "dev", Name: "sandbox", UID: "uid-other"},
	} {
		connection := testConnection(dir, filepath.Join(dir, "sshconfig"))
		connection.Sandbox = sandbox
		if err := saveJSON(filepath.Join(dir, sandbox.UID+".json"), connection); err != nil {
			t.Fatal(err)
		}
	}
	target := KubeTarget{Context: "other", Namespace: "dev"}
	connection, err := disconnect(context.Background(), &target, "sandbox", dir)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Sandbox.UID != "uid-other" {
		t.Fatalf("disconnect matched %q; want uid-other", connection.Sandbox.UID)
	}
	if _, err := disconnect(context.Background(), nil, "sandbox", dir); err == nil {
		t.Fatal("an unscoped disconnect accepted an ambiguous name")
	}
}

func TestRemoveConnectionRefusesPathsOutsideStateDir(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	outside := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(outside, []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := testConnection(stateDir, filepath.Join(dir, "sshconfig"))
	connection.SSH.KnownHostsFile = outside
	saved := &savedConnection{File: filepath.Join(stateDir, "sandbox-uid.json"), Connection: connection}
	if err := removeConnection(context.Background(), saved); err == nil {
		t.Fatal("removeConnection accepted a known hosts path outside the state directory")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was removed: %v", err)
	}

	allowed := testConnection(stateDir, filepath.Join(dir, "sshconfig"))
	saved = &savedConnection{File: filepath.Join(stateDir, "sandbox-uid.json"), Connection: allowed}
	if err := ensureSSHFiles(allowed, saved.File); err != nil {
		t.Fatal(err)
	}
	if err := removeConnection(context.Background(), saved); err != nil {
		t.Fatalf("removeConnection rejected its own state paths: %v", err)
	}
	for _, path := range []string{allowed.SSH.KnownHostsFile, allowed.SSH.EntryFile, allowed.SSH.ProxyFile, saved.File} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after removeConnection", path)
		}
	}
}
