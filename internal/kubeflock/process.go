package kubeflock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

type commandError struct {
	Stderr   string
	Stdout   string
	ExitCode int
	TimedOut bool
	Cause    error
}

func (e *commandError) Error() string {
	if e.Stderr != "" {
		return e.Stderr
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return fmt.Sprintf("command exited with status %d", e.ExitCode)
}

func commandContext(ctx context.Context, command string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return cmd
}

func runCaptured(ctx context.Context, command string, args, env []string, stdin io.Reader) (string, error) {
	cmd := commandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), nil
	}
	code := -1
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		code = exit.ExitCode()
	}
	return "", &commandError{Stderr: stderr.String(), Stdout: stdout.String(), ExitCode: code, TimedOut: ctx.Err() != nil, Cause: err}
}

func relay(ctx context.Context, command string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := commandContext(ctx, command, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), nil
	}
	return 1, err
}
