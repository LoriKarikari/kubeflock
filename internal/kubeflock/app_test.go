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

func TestConfigCommandSavesVerifiedTarget(t *testing.T) {
	dir := t.TempDir()
	kubectl := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(kubectl, []byte("#!/bin/sh\nprintf 'homelab\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yaml")
	var output, stderr strings.Builder
	app := NewApp(strings.NewReader(""), &output, &stderr)
	status := app.Run(context.Background(), []string{
		"--config", config,
		"--kubectl", kubectl,
		"cluster", "config",
		"--context", "homelab",
		"--namespace", "developer",
	})
	if status != 0 {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
	got, err := loadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if got != (KubeTarget{Context: "homelab", Namespace: "developer"}) {
		t.Fatalf("config = %#v", got)
	}
}

func TestCreateOrRestoreRejectsProjectOnRestore(t *testing.T) {
	var output, stderr strings.Builder
	app := NewApp(strings.NewReader(""), &output, &stderr)
	_, err := app.createOrRestore(context.Background(), KubeTarget{Context: "test", Namespace: "dev"}, "sandbox", "uid-1", createOptions{
		Project: &projectRequest{Repository: "https://example.test/repo.git"},
	})
	if err == nil || !strings.Contains(err.Error(), "does not accept --repository") {
		t.Fatalf("createOrRestore = %v", err)
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
