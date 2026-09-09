package kubeflock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type App struct {
	In       io.Reader
	Out, Err io.Writer
	Now      func() time.Time
}

type exitError struct {
	code int
}

func (e exitError) Error() string { return "" }

func NewApp(in io.Reader, out, stderr io.Writer) *App {
	return &App{In: in, Out: out, Err: stderr, Now: time.Now}
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) Run(ctx context.Context, args []string) int {
	root := a.command()
	root.SetArgs(args)
	root.SetIn(a.In)
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	if err := root.ExecuteContext(ctx); err != nil {
		var exit exitError
		if errors.As(err, &exit) {
			return exit.code
		}
		fmt.Fprintf(a.Err, "kubeflock: %s\n", sanitizeLines(err.Error()))
		return 2
	}
	return 0
}

func (a *App) command() *cobra.Command {
	options := globalOptions{}
	root := &cobra.Command{
		Use:           "kubeflock",
		Short:         "Herdr agent environments on Kubernetes",
		Version:       Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_ = command.Help()
			return exitError{code: 2}
		},
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetVersionTemplate("kubeflock {{.Version}}\n")
	flags := root.PersistentFlags()
	flags.StringVar(&options.ConfigPath, "config", defaultConfigPath(), "config file")
	flags.StringVar(&options.Kubeconfig, "kubeconfig", "", "kubeconfig file")
	flags.StringVar(&options.Kubectl, "kubectl", envPath("KUBEFLOCK_KUBECTL", "kubectl"), "kubectl binary")
	flags.StringVar(&options.StateDir, "state-dir", defaultStateDir(), "connection state directory")
	root.AddCommand(&cobra.Command{Use: "version", Args: cobra.NoArgs, Run: func(*cobra.Command, []string) { fmt.Fprintf(a.Out, "kubeflock %s\n", Version) }})
	root.AddCommand(a.clusterCommand(&options), a.sandboxCommand(&options))
	return root
}

func (a *App) clusterCommand(options *globalOptions) *cobra.Command {
	cluster := &cobra.Command{Use: "cluster", Args: cobra.NoArgs}
	cluster.AddCommand(a.configCommand(options), a.checkCommand(options))
	return cluster
}

func (a *App) configCommand(options *globalOptions) *cobra.Command {
	var contextName, namespace string
	config := &cobra.Command{
		Use:  "config",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if contextName == "" || namespace == "" {
				return errors.New("--context and --namespace are required")
			}
			target := KubeTarget{Context: contextName, Namespace: namespace}
			if err := validateTarget(target); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(command.Context(), 15*time.Second)
			defer cancel()
			out, err := a.runKubectl(ctx, *options, "config", "get-contexts", "-o", "name")
			if err != nil {
				return fmt.Errorf("could not read kubeconfig contexts: %s", truncate(sanitizeLines(commandDetail(err)), 200))
			}
			if !slices.Contains(strings.Fields(out), target.Context) {
				return fmt.Errorf("context %q not found in kubeconfig; list with: kubectl config get-contexts", target.Context)
			}
			if err := saveConfig(options.ConfigPath, target); err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "saved target context=%q namespace=%q to %s\n", target.Context, target.Namespace, options.ConfigPath)
			return nil
		},
	}
	config.Flags().StringVar(&contextName, "context", "", "Kubernetes context")
	config.Flags().StringVar(&namespace, "namespace", "", "Kubernetes namespace")
	var output string
	show := &cobra.Command{
		Use:  "show",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			switch output {
			case "json":
				return writeJSON(a.Out, map[string]string{"context": target.Context, "namespace": target.Namespace, "config": options.ConfigPath})
			case "text":
				fmt.Fprintf(a.Out, "context:   %s\nnamespace: %s\nconfig:    %s\n", target.Context, target.Namespace, options.ConfigPath)
				return nil
			default:
				return fmt.Errorf("unknown --output %q", output)
			}
		},
	}
	show.Flags().StringVar(&output, "output", "text", "output format")
	config.AddCommand(show)
	return config
}

func (a *App) checkCommand(options *globalOptions) *cobra.Command {
	var output string
	var timeout, requestTimeout time.Duration
	check := &cobra.Command{
		Use:  "check",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("unknown --output %q", output)
			}
			if requestTimeout < time.Second {
				requestTimeout = time.Second
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(command.Context(), timeout)
			defer cancel()
			report := a.runCheck(ctx, target, *options, requestTimeout)
			if ctx.Err() != nil {
				fmt.Fprintln(a.Err, "kubeflock: check timed out. Clear any stuck login helper, then rerun with a longer --timeout.")
				return exitError{code: 1}
			}
			if output == "json" {
				if err := writeJSON(a.Out, report); err != nil {
					return err
				}
			} else {
				printCheckReport(a.Out, report)
			}
			if !report.OK {
				return exitError{code: 1}
			}
			return nil
		},
	}
	check.Flags().StringVar(&output, "output", "text", "output format")
	check.Flags().DurationVar(&timeout, "timeout", time.Minute, "overall timeout")
	check.Flags().DurationVar(&requestTimeout, "request-timeout", 10*time.Second, "Kubernetes request timeout")
	return check
}

func (a *App) sandboxCommand(options *globalOptions) *cobra.Command {
	sandbox := &cobra.Command{Use: "sandbox", Args: cobra.NoArgs}
	sandbox.AddCommand(
		a.createCommand(options),
		a.listCommand(options),
		a.connectCommand("connect", options),
		a.connectCommand("reconnect", options),
		a.disconnectCommand(options),
		a.proxyCommand(),
		a.createActionCommand(),
		a.createWizardCommand(options),
	)
	return sandbox
}

func (a *App) createCommand(options *globalOptions) *cobra.Command {
	var template, identity string
	var timeout time.Duration
	command := &cobra.Command{
		Use:  "create NAME",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if template == "" || identity == "" {
				return errors.New("sandbox create requires NAME, --template, and --identity")
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			created, err := a.createSandbox(command.Context(), target, args[0], createOptions{Template: template, IdentityFile: identity, Timeout: timeout, Poll: 2 * time.Second, Global: *options})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "ready sandbox %s from %s; home %s (%s); connected as %s\n", created.Name, created.Template, created.Home.Name, created.Home.Capacity, created.SSHAlias)
			return nil
		},
	}
	command.Flags().StringVar(&template, "template", "", "approved SandboxTemplate")
	command.Flags().StringVar(&identity, "identity", "", "SSH identity file")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "provisioning timeout")
	return command
}

func (a *App) listCommand(options *globalOptions) *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:  "list",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("unknown --output %q", output)
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			statuses, err := a.listSandboxStatus(command.Context(), target, *options)
			if err != nil {
				return err
			}
			if output == "json" {
				return writeJSON(a.Out, statuses)
			}
			if len(statuses) == 0 {
				fmt.Fprintln(a.Out, "no Kubeflock sandboxes")
				return nil
			}
			for _, status := range statuses {
				detail := ""
				if status.Step != "" {
					detail = fmt.Sprintf(" (%s: %s)", status.Step, status.Message)
				}
				fmt.Fprintf(a.Out, "%s/%s\t%s%s\n", status.Namespace, status.Name, status.State, detail)
			}
			return nil
		},
	}
	command.Flags().StringVar(&output, "output", "text", "output format")
	return command
}

func (a *App) connectCommand(name string, options *globalOptions) *cobra.Command {
	var identity string
	command := &cobra.Command{
		Use:  name + " [NAME]",
		Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			sandboxName := ""
			if len(args) == 1 {
				sandboxName = args[0]
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			connection, err := a.connect(command.Context(), target, connectOptions{Name: sandboxName, IdentityFile: identity, Global: *options})
			if err != nil {
				return err
			}
			verb := "reconnected"
			if name == "connect" {
				verb = "connected"
			}
			fmt.Fprintf(a.Out, "%s sandbox %s/%s as %s\n", verb, connection.Sandbox.Namespace, connection.Sandbox.Name, connection.SSH.Alias)
			return nil
		},
	}
	command.Flags().StringVar(&identity, "identity", "", "SSH identity file")
	return command
}

func (a *App) disconnectCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:  "disconnect [NAME]",
		Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			connection, err := a.disconnect(command.Context(), name, options.StateDir)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "disconnected sandbox %s/%s; remote processes are still running\n", connection.Sandbox.Namespace, connection.Sandbox.Name)
			return nil
		},
	}
}

func (a *App) proxyCommand() *cobra.Command {
	var state string
	command := &cobra.Command{
		Use:    "proxy",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if state == "" {
				return errors.New("sandbox proxy requires --state")
			}
			code, err := a.runProxy(command.Context(), state)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitError{code: code}
			}
			return nil
		},
	}
	command.Flags().StringVar(&state, "state", "", "connection state file")
	return command
}

func (a *App) createActionCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "create-action",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			args := []string{"plugin", "pane", "open", "--plugin", envPath("HERDR_PLUGIN_ID", "kubeflock"), "--entrypoint", "create", "--focus"}
			if workspace := os.Getenv("HERDR_WORKSPACE_ID"); workspace != "" {
				args = append(args, "--workspace", workspace)
			}
			_, err := a.runHerdr(command.Context(), args...)
			return err
		},
	}
}

func (a *App) createWizardCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "create-wizard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var name, template, identity, confirmed string
			fmt.Fprint(a.Out, "Sandbox name: ")
			if _, err := fmt.Fscanln(a.In, &name); err != nil {
				return err
			}
			fmt.Fprint(a.Out, "Approved template: ")
			if _, err := fmt.Fscanln(a.In, &template); err != nil {
				return err
			}
			fmt.Fprint(a.Out, "SSH identity file: ")
			if _, err := fmt.Fscanln(a.In, &identity); err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "Create %s from %s with persistent home storage? [y/N] ", name, template)
			fmt.Fscanln(a.In, &confirmed)
			if strings.ToLower(confirmed) != "y" && strings.ToLower(confirmed) != "yes" {
				fmt.Fprintln(a.Out, "cancelled; no cluster resources were changed")
				return nil
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			created, err := a.createSandbox(command.Context(), target, name, createOptions{Template: template, IdentityFile: identity, Timeout: 5 * time.Minute, Poll: 2 * time.Second, Global: *options})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "ready sandbox %s from %s; home %s (%s); connected as %s\n", created.Name, created.Template, created.Home.Name, created.Home.Capacity, created.SSHAlias)
			return nil
		},
	}
}

func printCheckReport(out io.Writer, report CheckReport) {
	fmt.Fprintf(out, "Kubeflock cluster check: context=%q namespace=%q\n", report.Context, report.Namespace)
	passed := 0
	for _, check := range report.Checks {
		mark := "FAIL"
		if check.OK {
			mark = "ok"
			passed++
		} else if check.Advisory {
			mark = "warn"
		}
		fmt.Fprintf(out, "  [%s] %s: %s\n", mark, check.Name, check.Message)
		if !check.OK && check.Remediation != "" {
			fmt.Fprintf(out, "         fix: %s\n", check.Remediation)
		}
		if !check.OK && check.Category != "" {
			fmt.Fprintf(out, "         category: %s\n", check.Category)
		}
	}
	if report.OK {
		fmt.Fprintf(out, "PASS: %d/%d checks passed\n", passed, len(report.Checks))
	} else {
		fmt.Fprintf(out, "FAIL: %d/%d checks passed; fix the FAIL rows and rerun\n", passed, len(report.Checks))
	}
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
