package kubeflock

import (
	"bufio"
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

const homeDeleteTimeout = 5 * time.Minute

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
		a.retainCommand(options),
		a.homeCommand(options),
		a.disconnectCommand(options),
		a.proxyCommand(),
		createActionCommand("create"),
		createActionCommand("restore"),
		createActionCommand("delete-home"),
		a.createWizardCommand(options),
		a.restoreWizardCommand(options),
		a.deleteHomeWizardCommand(options),
	)
	return sandbox
}

func (a *App) createCommand(options *globalOptions) *cobra.Command {
	var template, identity, homeUID string
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
			created, err := a.createOrRestore(command.Context(), target, args[0], homeUID, createOptions{
				Template:     template,
				IdentityFile: identity,
				Timeout:      timeout,
				Poll:         2 * time.Second,
				Global:       *options,
			})
			if err != nil {
				return err
			}
			return a.reportCreated(created, homeUID != "")
		},
	}
	command.Flags().StringVar(&template, "template", "", "approved SandboxTemplate")
	command.Flags().StringVar(&identity, "identity", "", "SSH identity file")
	command.Flags().StringVar(&homeUID, "home", "", "retained home PVC UID to restore")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "provisioning or checkout timeout")
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

func (a *App) retainCommand(options *globalOptions) *cobra.Command {
	var timeout time.Duration
	command := &cobra.Command{
		Use:  "delete [NAME]",
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
			retained, err := retainSandboxHome(command.Context(), target, name, lifecycleOptions{
				Timeout: timeout,
				Poll:    2 * time.Second,
				Global:  *options,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "deleted sandbox %s/%s; retained home %s (%s)\n", target.Namespace, retained.Name, retained.Home.Name, retained.Home.Capacity)
			return nil
		},
	}
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "deletion timeout")
	return command
}

func (a *App) homeCommand(options *globalOptions) *cobra.Command {
	home := &cobra.Command{Use: "home", Args: cobra.NoArgs}
	output := outputText
	list := &cobra.Command{
		Use:  "list",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			homes, err := listRetainedHomes(options.StateDir)
			if err != nil {
				return err
			}
			homes = slices.DeleteFunc(homes, func(home RetainedHome) bool {
				return home.Origin.Context != target.Context || home.Origin.Namespace != target.Namespace
			})
			if output == outputJSON {
				return writeJSON(a.Out, homes)
			}
			if len(homes) == 0 {
				fmt.Fprintln(a.Out, "no retained homes")
				return nil
			}
			for _, retained := range homes {
				residual := ""
				if retained.Deletion != nil {
					residual = fmt.Sprintf(" pv=%s pvUID=%s", retained.Deletion.Name, retained.Deletion.UID)
				}
				fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\tuid=%s origin=%s/%s template=%s%s\n", retained.Home.Name, retained.State, retained.Home.Capacity, retained.Home.StorageClass, retained.Home.UID, retained.Origin.Namespace, retained.allocationName(), retained.Template, residual)
			}
			return nil
		},
	}
	output.declare(list)
	var confirmation string
	var timeout time.Duration
	deleteHome := &cobra.Command{
		Use:  "delete UID",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			return a.deleteHome(command.Context(), target, args[0], confirmation, timeout, *options)
		},
	}
	deleteHome.Flags().StringVar(&confirmation, "confirm", "", "confirm permanent deletion by repeating the PVC UID")
	deleteHome.Flags().DurationVar(&timeout, "timeout", homeDeleteTimeout, "storage deletion timeout")
	home.AddCommand(list, deleteHome)
	return home
}

func (a *App) deleteHome(ctx context.Context, target KubeTarget, uid, confirmation string, timeout time.Duration, options globalOptions) error {
	selection, err := inspectRetainedHomeDeletion(ctx, target, uid, lifecycleOptions{Timeout: timeout, Poll: 2 * time.Second, Global: options})
	if err != nil {
		return err
	}
	home := selection.Retained.Home
	fmt.Fprintf(a.Out, "Permanent storage deletion\n  target: %s/%s\n  home: %s\n  PVC UID: %s\n  capacity: %s\n  storage class: %s\n", target.Context, target.Namespace, home.Name, home.UID, home.Capacity, home.StorageClass)
	if selection.Volume != nil {
		fmt.Fprintf(a.Out, "  persistent volume: %s\n", selection.Volume.Name)
	}
	fmt.Fprint(a.Out, "This deletes project files, history, settings, and credentials saved in this home.\n")
	if confirmation == "" {
		fmt.Fprintf(a.Out, "Type the PVC UID %s to confirm: ", uid)
		if _, err := fmt.Fscanln(a.In, &confirmation); err != nil {
			confirmation = ""
		}
	}
	if confirmation == "" {
		return errors.New("confirmation was empty; no storage was deleted")
	}
	if confirmation != uid {
		return fmt.Errorf("confirmation %q does not match PVC UID %s; no storage was deleted", confirmation, uid)
	}
	if err := deleteRetainedHome(ctx, target, uid, lifecycleOptions{Timeout: timeout, Poll: 2 * time.Second, Global: options}); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "permanently deleted retained home %s (PVC UID %s)\n", home.Name, home.UID)
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

func (a *App) createOrRestore(ctx context.Context, target KubeTarget, name, homeUID string, options createOptions) (createdSandbox, error) {
	if homeUID == "" {
		return createSandbox(ctx, target, name, nil, options)
	}
	selection, err := inspectRestore(ctx, target, name, homeUID, options)
	if err != nil {
		return createdSandbox{}, err
	}
	fmt.Fprintf(a.Err, "restoring home %s (UID %s) as %s/%s with template %s image %s\n", selection.Retained.Home.Name, selection.Retained.Home.UID, target.Namespace, name, selection.Approved.Name, selection.Approved.Image)
	return createSandbox(ctx, target, name, &selection, options)
}

func (a *App) createWizardCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "create-wizard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(a.In)
			prompt := func(label string) (string, error) {
				fmt.Fprint(a.Out, label)
				if !scanner.Scan() {
					return "", cmp.Or(scanner.Err(), io.EOF)
				}
				return strings.TrimSpace(scanner.Text()), nil
			}
			name, err := prompt("Sandbox name: ")
			if err != nil {
				return err
			}
			template, err := prompt("Approved template: ")
			if err != nil {
				return err
			}
			identity, err := prompt("SSH identity file: ")
			if err != nil {
				return err
			}
			confirmed, err := prompt(fmt.Sprintf("Create %s from %s with persistent home storage? [y/N] ", name, template))
			if err != nil {
				return err
			}
			if !slices.Contains([]string{"y", "yes"}, strings.ToLower(confirmed)) {
				fmt.Fprintln(a.Out, "cancelled; no cluster resources were changed")
				return nil
			}
			created, err := a.createOrRestore(command.Context(), target, name, "", createOptions{
				Template:     template,
				IdentityFile: identity,
				Timeout:      5 * time.Minute,
				Poll:         2 * time.Second,
				Global:       *options,
			})
			if err != nil {
				return err
			}
			return a.reportCreated(created, false)
		},
	}
}

func (a *App) reportCreated(created createdSandbox, restored bool) error {
	if restored {
		fmt.Fprintf(a.Out, "ready sandbox %s; restored home %s; connected to Herdr\n", created.Name, created.Home.Name)
	} else {
		fmt.Fprintf(a.Out, "ready sandbox %s; connected to Herdr\n", created.Name)
	}
	return nil
}

func (a *App) restoreWizardCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "restore-wizard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var homeUID, name, template, identity, confirmed string
			fmt.Fprint(a.Out, "Retained home UID: ")
			if _, err := fmt.Fscanln(a.In, &homeUID); err != nil {
				return err
			}
			fmt.Fprint(a.Out, "Replacement sandbox name: ")
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
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			create := createOptions{Template: template, IdentityFile: identity, Timeout: 5 * time.Minute, Poll: 2 * time.Second, Global: *options}
			selection, err := inspectRestore(command.Context(), target, name, homeUID, create)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "Restore %s as %s with template %s image %s? [y/N] ", selection.Retained.Home.Name, name, selection.Approved.Name, selection.Approved.Image)
			if _, err := fmt.Fscanln(a.In, &confirmed); err != nil {
				return err
			}
			if !slices.Contains([]string{"y", "yes"}, strings.ToLower(confirmed)) {
				fmt.Fprintln(a.Out, "cancelled; no cluster resources were changed")
				return nil
			}
			created, err := createSandbox(command.Context(), target, name, &selection, create)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "ready sandbox %s; restored home %s; connected to Herdr\n", created.Name, created.Home.Name)
			return nil
		},
	}
}

func (a *App) deleteHomeWizardCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "delete-home-wizard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			var uid string
			fmt.Fprint(a.Out, "Retained home PVC UID: ")
			if _, err := fmt.Fscanln(a.In, &uid); err != nil {
				return err
			}
			target, err := loadConfig(options.ConfigPath)
			if err != nil {
				return err
			}
			return a.deleteHome(command.Context(), target, uid, "", homeDeleteTimeout, *options)
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
