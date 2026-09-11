package kubeflock

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type App struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	Now func() time.Time
}

const workspaceDeleteTimeout = 5 * time.Minute

type exitError struct {
	code int
}

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

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
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if exit, ok := errors.AsType[exitError](err); ok {
		return exit.code
	}
	fmt.Fprintf(a.Err, "kubeflock: %s\n", err)
	return 2
}

func (a *App) command() *cobra.Command {
	options := globalOptions{}
	root := &cobra.Command{
		Use:           "kubeflock",
		Short:         "Herdr agent environments on Kubernetes",
		Version:       Version,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			stateDir, err := filepath.Abs(options.StateDir)
			if err != nil {
				return err
			}
			options.StateDir = stateDir
			return nil
		},
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(command *cobra.Command, _ []string) error {
			if err := command.Help(); err != nil {
				return err
			}
			return exitError{code: 2}
		},
	}
	root.SetVersionTemplate("kubeflock {{.Version}}\n")
	root.SetIn(a.In)
	root.SetOut(a.Out)
	root.SetErr(a.Err)

	flags := root.PersistentFlags()
	flags.StringVar(&options.ConfigPath, "config", defaultConfigPath(), "config file")
	flags.StringVar(&options.Kubeconfig, "kubeconfig", "", "kubeconfig file")
	flags.StringVar(&options.Kubectl, "kubectl", cmp.Or(os.Getenv("KUBEFLOCK_KUBECTL"), "kubectl"), "kubectl binary")
	flags.StringVar(&options.StateDir, "state-dir", defaultStateDir(), "connection state directory")

	root.AddCommand(a.versionCommand(), a.clusterCommand(&options), a.sandboxCommand(&options))
	return root
}

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:  "version",
		Args: cobra.NoArgs,
		Run:  func(*cobra.Command, []string) { fmt.Fprintf(a.Out, "kubeflock %s\n", Version) },
	}
}

func (a *App) clusterCommand(options *globalOptions) *cobra.Command {
	cluster := &cobra.Command{Use: "cluster", Args: cobra.NoArgs}
	cluster.AddCommand(a.configCommand(options), a.checkCommand(options))
	return cluster
}

func (a *App) configCommand(options *globalOptions) *cobra.Command {
	var target KubeTarget
	config := &cobra.Command{
		Use:  "config",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return a.saveTarget(command.Context(), *options, target)
		},
	}
	config.Flags().StringVar(&target.Context, "context", "", "Kubernetes context")
	config.Flags().StringVar(&target.Namespace, "namespace", "", "Kubernetes namespace")
	config.AddCommand(a.configShowCommand(options))
	return config
}

func (a *App) saveTarget(ctx context.Context, options globalOptions, target KubeTarget) error {
	if target.Context == "" || target.Namespace == "" {
		return errors.New("--context and --namespace are required")
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := runKubectl(ctx, options, "config", "get-contexts", "-o", "name")
	if err != nil {
		return fmt.Errorf("read kubeconfig contexts: %w", err)
	}
	if !slices.Contains(strings.Fields(out), target.Context) {
		return fmt.Errorf("context %q not found in kubeconfig; list with: kubectl config get-contexts", target.Context)
	}
	if err := saveConfig(options.ConfigPath, target); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "saved target context=%q namespace=%q to %s\n", target.Context, target.Namespace, options.ConfigPath)
	return nil
}

func (a *App) configShowCommand(options *globalOptions) *cobra.Command {
	output := outputText
	show := &cobra.Command{
		Use:  "show",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			if output == outputJSON {
				return writeJSON(a.Out, savedConfig{Context: target.Context, Namespace: target.Namespace, Config: options.ConfigPath})
			}
			fmt.Fprintf(a.Out, "context:   %s\nnamespace: %s\nconfig:    %s\n", target.Context, target.Namespace, options.ConfigPath)
			return nil
		},
	}
	output.declare(show)
	return show
}

func (a *App) checkCommand(options *globalOptions) *cobra.Command {
	output := outputText
	var timeout, requestTimeout time.Duration
	check := &cobra.Command{
		Use:  "check",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
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
			if output == outputJSON {
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
	output.declare(check)
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
		a.lifecycleCommand("stop", modeSuspended, options),
		a.lifecycleCommand("resume", modeRunning, options),
		a.deleteCommand(options),
		a.disconnectCommand(options),
		a.proxyCommand(),
		createActionCommand("create"),
		createActionCommand("delete"),
		a.createWizardCommand(options),
		a.deleteWizardCommand(options),
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
			created, err := createSandbox(command.Context(), target, args[0], createOptions{
				Template:     template,
				IdentityFile: identity,
				Timeout:      timeout,
				Poll:         2 * time.Second,
				Global:       *options,
			})
			if err != nil {
				return err
			}
			a.reportCreated(created)
			return nil
		},
	}
	command.Flags().StringVar(&template, "template", "", "approved SandboxTemplate")
	command.Flags().StringVar(&identity, "identity", "", "SSH identity file")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "provisioning timeout")
	return command
}

func (a *App) listCommand(options *globalOptions) *cobra.Command {
	output := outputText
	command := &cobra.Command{
		Use:  "list",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			statuses, err := listSandboxStatus(command.Context(), target, *options)
			if err != nil {
				return err
			}
			if output == outputJSON {
				return writeJSON(a.Out, statuses)
			}
			printSandboxStatuses(a.Out, statuses)
			return nil
		},
	}
	output.declare(command)
	return command
}

func printSandboxStatuses(out io.Writer, statuses []SandboxStatus) {
	if len(statuses) == 0 {
		fmt.Fprintln(out, "no Kubeflock sandboxes")
		return
	}
	for _, status := range statuses {
		detail := ""
		if status.Step != "" {
			detail = fmt.Sprintf(" (%s: %s)", status.Step, status.Message)
		}
		fmt.Fprintf(out, "%s/%s\t%s%s\n", status.Namespace, status.Name, status.State, detail)
	}
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
			connection, err := connect(command.Context(), target, connectOptions{Name: sandboxName, IdentityFile: identity, Global: *options})
			if err != nil {
				return err
			}
			verb := "reconnected"
			if name == "connect" {
				verb = "connected"
			}
			fmt.Fprintf(a.Out, "%s %s to Herdr\n", verb, connection.Sandbox.Name)
			return nil
		},
	}
	command.Flags().StringVar(&identity, "identity", "", "SSH identity file")
	return command
}

func (a *App) lifecycleCommand(verb string, mode sandboxOperatingMode, options *globalOptions) *cobra.Command {
	var timeout time.Duration
	command := &cobra.Command{
		Use:  verb + " [NAME]",
		Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Err, "requesting %s mode for sandbox %s\n", mode, cmp.Or(name, "in the configured target"))
			result, err := changeSandboxMode(command.Context(), target, name, mode, lifecycleOptions{
				Timeout: timeout,
				Poll:    2 * time.Second,
				Global:  *options,
			})
			if err != nil {
				return err
			}
			if mode == modeSuspended {
				fmt.Fprintf(a.Out, "stopped sandbox %s/%s; persistent home retained\n", target.Namespace, result.Name)
			} else {
				fmt.Fprintf(a.Out, "resumed sandbox %s/%s; connected as %s\n", target.Namespace, result.Name, result.SSHAlias)
			}
			return nil
		},
	}
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "lifecycle transition timeout")
	return command
}

func (a *App) deleteCommand(options *globalOptions) *cobra.Command {
	var confirmation string
	var timeout time.Duration
	command := &cobra.Command{
		Use:  "delete NAME",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			return a.deleteWorkspace(command.Context(), target, args[0], confirmation, timeout, *options)
		},
	}
	command.Flags().StringVar(&confirmation, "confirm", "", "confirm permanent deletion with DELETE")
	command.Flags().DurationVar(&timeout, "timeout", workspaceDeleteTimeout, "deletion timeout")
	return command
}

func (a *App) deleteWorkspace(ctx context.Context, target KubeTarget, name, confirmation string, timeout time.Duration, options globalOptions) error {
	fmt.Fprintf(a.Out, "Permanently delete sandbox %s/%s and its workspace data.\n", target.Namespace, name)
	if confirmation == "" {
		fmt.Fprint(a.Out, "Type DELETE to confirm: ")
		if _, err := fmt.Fscanln(a.In, &confirmation); err != nil {
			confirmation = ""
		}
	}
	if confirmation != "DELETE" {
		return errors.New("confirmation was not DELETE; nothing was deleted")
	}
	if err := permanentlyDeleteWorkspace(ctx, target, name, lifecycleOptions{Timeout: timeout, Poll: 2 * time.Second, Global: options}); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "permanently deleted sandbox %s/%s and its workspace data\n", target.Namespace, name)
	return nil
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
			target, err := loadSavedTarget(options.ConfigPath)
			if err != nil {
				return err
			}
			connection, err := disconnect(command.Context(), target, name, options.StateDir)
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

func createActionCommand(pane string) *cobra.Command {
	return &cobra.Command{
		Use:    pane + "-action",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			args := []string{
				"plugin", "pane", "open",
				"--plugin", cmp.Or(os.Getenv("HERDR_PLUGIN_ID"), "kubeflock"),
				"--entrypoint", pane,
				"--focus",
			}
			_, err := runHerdr(command.Context(), args...)
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
			return a.createPopup(command.Context(), *options)
		},
	}
}

func (a *App) reportCreated(created createdSandbox) {
	fmt.Fprintf(a.Out, "ready sandbox %s; connected to Herdr\n", created.Name)
}

func (a *App) deleteWizardCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "delete-wizard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var name string
			fmt.Fprint(a.Out, "Sandbox name: ")
			if _, err := fmt.Fscanln(a.In, &name); err != nil {
				return err
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			return a.deleteWorkspace(command.Context(), target, name, "", workspaceDeleteTimeout, *options)
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
	}
	if report.OK {
		fmt.Fprintf(out, "PASS: %d/%d checks passed\n", passed, len(report.Checks))
	} else {
		fmt.Fprintf(out, "FAIL: %d/%d checks passed; fix the FAIL rows and rerun\n", passed, len(report.Checks))
	}
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.Marshal(value, jsontext.WithIndent("  "), json.Deterministic(true))
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}

type outputFormat string

const (
	outputText outputFormat = "text"
	outputJSON outputFormat = "json"
)

func (f *outputFormat) String() string { return string(*f) }
func (f *outputFormat) Type() string   { return "format" }

func (f *outputFormat) Set(value string) error {
	switch outputFormat(value) {
	case outputText, outputJSON:
		*f = outputFormat(value)
		return nil
	}
	return errors.New("must be text or json")
}

func (f *outputFormat) declare(command *cobra.Command) {
	command.Flags().Var(f, "output", "output format")
}

type savedConfig struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Config    string `json:"config"`
}
