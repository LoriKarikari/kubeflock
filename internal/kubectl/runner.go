package kubectl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Runner executes kubectl with a hard outer bound that also cleans up
// credential-helper descendants sharing the process group.
//
// kubectl's --request-timeout alone does not bound exec credential helpers:
// a helper holding the OIDC cache lock can outlive the kubectl parent.
// Runner starts each command in its own process group and, on cancellation
// or timeout, signals the whole group with SIGTERM then escalates to SIGKILL
// after TermGrace so a helper that ignores termination cannot hold the lock.
type Runner struct {
	// KubectlPath is the kubectl binary. Defaults to "kubectl".
	KubectlPath string
	// Kubeconfig optionally sets KUBECONFIG for the child.
	Kubeconfig string
	// TermGrace is the delay between SIGTERM and SIGKILL on timeout.
	// Defaults to 2s when non-positive.
	TermGrace time.Duration
}

func (r Runner) bin() string {
	if r.KubectlPath != "" {
		return r.KubectlPath
	}
	return "kubectl"
}

func (r Runner) grace() time.Duration {
	if r.TermGrace > 0 {
		return r.TermGrace
	}
	return 2 * time.Second
}

// Run executes kubectl args and returns combined stdout. Stderr is included
// in the error for classification. The call respects ctx cancellation and
// guarantees no descendant in the command's process group is left behind.
func (r Runner) Run(ctx context.Context, args ...string) (string, error) {
	bin := r.bin()
	cmd := exec.CommandContext(context.Background(), bin, args...)
	if r.Kubeconfig != "" {
		cmd.Env = append(cmd.Environ(), "KUBECONFIG="+r.Kubeconfig)
	}
	// New process group so helpers spawned by kubectl stay in our group
	// and die with it on timeout/cancel.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start kubectl: %w", err)
	}
	pgid, pgidErr := syscall.Getpgid(cmd.Process.Pid)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var ctxErr error
	select {
	case err := <-done:
		// Command exited; still sweep the group in case a helper
		// outlived its kubectl parent while holding the OIDC lock.
		r.killGroup(pgid, pgidErr, true)
		if err != nil {
			return stdout.String(), &Error{
				Args:   append([]string{bin}, args...),
				Stderr: stderr.String(),
				Err:    err,
			}
		}
		return stdout.String(), nil
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}

	// Bound exceeded: TERM the group, escalate to KILL, then reap.
	r.killGroup(pgid, pgidErr, false)
	select {
	case <-done:
	case <-time.After(r.grace() + 5*time.Second):
	}
	// Final sweep: a helper that ignored SIGTERM must not survive.
	r.killGroup(pgid, pgidErr, true)

	if ctxErr == nil {
		ctxErr = context.DeadlineExceeded
	}
	return stdout.String(), &Error{
		Args:    append([]string{bin}, args...),
		Stderr:  stderr.String(),
		Err:     fmt.Errorf("kubectl timed out or cancelled: %w", ctxErr),
		Timeout: true,
	}
}

// killGroup signals the process group. When force is true it sends SIGKILL,
// otherwise SIGTERM followed by delayed SIGKILL by the caller.
func (r Runner) killGroup(pgid int, pgidErr error, force bool) {
	if pgidErr != nil || pgid <= 0 {
		return
	}
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	_ = syscall.Kill(-pgid, sig)
	if !force {
		grace := r.grace()
		go func() {
			time.Sleep(grace)
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}()
	}
}

// Error carries kubectl stderr for classification without leaking argv
// secrets to callers that only log messages.
type Error struct {
	Args    []string
	Stderr  string
	Err     error
	Timeout bool
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Stderr != "" {
		return fmt.Sprintf("kubectl failed: %v: %s", e.Err, firstLine(e.Stderr))
	}
	return fmt.Sprintf("kubectl failed: %v", e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// TimeoutError reports whether err came from a runner deadline/cancel.
func TimeoutError(err error) bool {
	var ke *Error
	if errors.As(err, &ke) {
		return ke.Timeout
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}
