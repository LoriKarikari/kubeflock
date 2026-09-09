package kubeflock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeflock", "config.yaml")
	want := KubeTarget{Context: "homelab", Namespace: "kubeflock-check"}
	if err := saveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("loadConfig = %#v; want %#v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestSanitizeAndClassify(t *testing.T) {
	input := "Bearer abc.def.ghi\naccess_token=secret123\nhttps://example.test/authorize?code=supersecret&state=x\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-part-here"
	got := sanitizeLines(input)
	for _, secret := range []string{"abc.def.ghi", "secret123", "supersecret", "eyJhbGci"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitizeLines leaked %q", secret)
		}
	}
	cases := []struct {
		message string
		timeout bool
		want    string
	}{{"Error from server (Forbidden): sandboxes is forbidden", false, "denied"}, {"Unauthorized: ID token expired", false, "expired-authentication"}, {"Unable to connect: dial tcp: connection refused", false, "connectivity"}, {`context "x" not found`, false, "configuration"}, {`runtimeclass "gvisor" not found`, false, "missing-infrastructure"}, {"", true, "timeout"}, {"strange", false, "unknown"}}
	for _, test := range cases {
		if got := classify(test.message, test.timeout); got != test.want {
			t.Errorf("classify(%q) = %q; want %q", test.message, got, test.want)
		}
	}
}

func TestRunCapturedKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "kubectl")
	body := "#!/bin/sh\n( trap '' TERM; exec sleep 30 ) &\necho $! > '" + childFile + "'\ntrap '' TERM\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := runCaptured(ctx, script, nil, nil, nil); err == nil {
		t.Fatal("expected timeout")
	}
	pidData, err := os.ReadFile(childFile)
	if err != nil {
		t.Fatal(err)
	}
	pid := 0
	if _, err := fmt.Sscan(string(pidData), &pid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatalf("child %d survived timeout", pid)
	}
}

func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
