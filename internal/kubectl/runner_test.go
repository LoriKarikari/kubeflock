package kubectl

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeExe(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunSuccess(t *testing.T) {
	dir := t.TempDir()
	fake := writeExe(t, dir, "kubectl", "#!/bin/sh\necho hello-stdout\n")
	r := Runner{KubectlPath: fake}
	out, err := r.Run(context.Background(), "get", "pods")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(out) != "hello-stdout" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestRunTimeoutKillsHelperIgnoringTERM(t *testing.T) {
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child.pid")
	// Fake kubectl spawns a helper child that ignores SIGTERM (like a stuck
	// OIDC credential helper holding the cache lock), then waits. Both must
	// die on timeout via SIGKILL escalation.
	fake := writeExe(t, dir, "kubectl", `#!/bin/sh
echo $$ > "`+dir+`/parent.pid"
( trap '' TERM; exec sleep 30 ) &
echo $! > "`+childFile+`"
trap '' TERM
exec sleep 30
`)
	r := Runner{KubectlPath: fake, TermGrace: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Run(ctx, "--context", "saved", "get", "pods")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want timeout error, got nil")
	}
	if !TimeoutError(err) {
		t.Fatalf("want timeout error, got %v", err)
	}
	// Runner must escalate quickly, not wait for the 30s sleeps.
	if elapsed > 10*time.Second {
		t.Fatalf("escalation too slow: %v", elapsed)
	}
	// Child helper must be gone: no descendant may hold the OIDC lock.
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, readErr := os.ReadFile(childFile)
		if readErr != nil {
			t.Fatalf("child pid file missing: %v", readErr)
		}
		pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if convErr != nil {
			t.Fatalf("bad pid: %v", convErr)
		}
		if err := syscall.Kill(pid, 0); err != nil {
			break // gone (ESRCH) — success
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper child %d still alive after timeout; OIDC lock could be held", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunCancelCleansGroup(t *testing.T) {
	dir := t.TempDir()
	fake := writeExe(t, dir, "kubectl", "#!/bin/sh\ntrap '' TERM\nexec sleep 30\n")
	r := Runner{KubectlPath: fake, TermGrace: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	_, err := r.Run(ctx, "get", "pods")
	if err == nil {
		t.Fatal("want cancel error")
	}
	if !TimeoutError(err) {
		t.Fatalf("want timeout/cancel error, got %v", err)
	}
}
