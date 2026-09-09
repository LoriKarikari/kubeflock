package kubeflock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

func TestClassify(t *testing.T) {
	cases := []struct {
		message string
		timeout bool
		want    string
	}{
		{message: "Error from server (Forbidden): sandboxes is forbidden", want: "denied"},
		{message: "Unauthorized: ID token expired", want: "expired-authentication"},
		{message: "Unable to connect: dial tcp: connection refused", want: "connectivity"},
		{message: `context "x" not found`, want: "configuration"},
		{message: `runtimeclass "gvisor" not found`, want: "missing-infrastructure"},
		{timeout: true, want: "timeout"},
		{message: "strange", want: "unknown"},
	}
	for _, test := range cases {
		if got := classify(test.message, test.timeout); got != test.want {
			t.Errorf("classify(%q) = %q; want %q", test.message, got, test.want)
		}
	}
}

func TestCommandErrorHidesOutput(t *testing.T) {
	err := &commandError{Stderr: "access_token=secret", Stdout: "secret", ExitCode: 1}
	if got := err.Error(); got != "command exited with status 1" {
		t.Fatalf("Error() = %q", got)
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
