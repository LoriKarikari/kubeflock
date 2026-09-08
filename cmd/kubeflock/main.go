package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/LoriKarikari/kubeflock/internal/check"
	"github.com/LoriKarikari/kubeflock/internal/config"
	"github.com/LoriKarikari/kubeflock/internal/kubectl"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kubeflock: "+err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	if len(argv) == 0 {
		printUsage()
		return fmt.Errorf("missing command")
	}
	switch argv[0] {
	case "-h", "--help", "help":
		printUsage()
		return nil
	case "-V", "--version", "version":
		fmt.Println("kubeflock " + version)
		return nil
	case "cluster":
		return runCluster(argv[1:])
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", argv[0])
	}
}

func printUsage() {
	fmt.Println(`kubeflock - Herdr agent environments on Kubernetes

Usage:
  kubeflock cluster config --context NAME --namespace NAME
  kubeflock cluster config show [--output text|json]
  kubeflock cluster check [--timeout 60s] [--output text|json]
  kubeflock version

Global flags (each subcommand):
  --config PATH       config file (default $KUBEFLOCK_CONFIG or ~/.config/kubeflock/config.yaml)
  --kubeconfig PATH   kubeconfig file (default $KUBECONFIG or ~/.kube/config)
  --kubectl PATH      kubectl binary (default kubectl)

The saved context pins Kubeflock's target. Changing kubectl's current
context never retargets Kubeflock; every check passes --context explicitly.`)
}

func runCluster(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("missing cluster subcommand (config, check)")
	}
	switch argv[0] {
	case "config":
		return runClusterConfig(argv[1:])
	case "check":
		return runClusterCheck(argv[1:])
	default:
		return fmt.Errorf("unknown cluster subcommand %q", argv[0])
	}
}

func runClusterConfig(argv []string) error {
	// Support both `config --context X` and `config show`.
	if len(argv) > 0 && argv[0] == "show" {
		return runClusterConfigShow(argv[1:])
	}
	fs := flag.NewFlagSet("kubeflock cluster config", flag.ContinueOnError)
	contextName := fs.String("context", "", "Kubernetes context to pin for Kubeflock")
	namespace := fs.String("namespace", "", "developer namespace for Kubeflock")
	configPath := fs.String("config", config.DefaultPath(), "config file")
	kubeconfig := fs.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig file")
	kubectlBin := fs.String("kubectl", defaultKubectl(), "kubectl binary")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *contextName == "" || *namespace == "" {
		fs.Usage()
		return fmt.Errorf("--context and --namespace are required")
	}
	cfg := config.Config{Context: *contextName, Namespace: *namespace}
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Validate the context exists in kubeconfig with a bounded read.
	// This is a local kubeconfig read, not a cluster write.
	if err := validateContext(*kubectlBin, *kubeconfig, *contextName); err != nil {
		return err
	}
	if err := config.Save(*configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("saved target context=%q namespace=%q to %s\n", cfg.Context, cfg.Namespace, *configPath)
	return nil
}

func runClusterConfigShow(argv []string) error {
	fs := flag.NewFlagSet("kubeflock cluster config show", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath(), "config file")
	output := fs.String("output", "text", "output format: text|json")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{"context": cfg.Context, "namespace": cfg.Namespace, "config": *configPath})
	case "text":
		fmt.Printf("context:   %s\nnamespace: %s\nconfig:    %s\n", cfg.Context, cfg.Namespace, *configPath)
		return nil
	default:
		return fmt.Errorf("unknown --output %q", *output)
	}
}

func runClusterCheck(argv []string) error {
	fs := flag.NewFlagSet("kubeflock cluster check", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath(), "config file")
	kubeconfig := fs.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig file")
	kubectlBin := fs.String("kubectl", defaultKubectl(), "kubectl binary")
	timeout := fs.Duration("timeout", 60*time.Second, "overall bound for the whole check, including credential helpers")
	reqTimeout := fs.Duration("request-timeout", 10*time.Second, "per-request API timeout passed to kubectl")
	output := fs.String("output", "text", "output format: text|json")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := check.Run(ctx, cfg, check.Options{
		Runner: kubectl.Runner{
			KubectlPath: *kubectlBin,
			Kubeconfig:  *kubeconfig,
		},
		RequestTimeout: *reqTimeout,
	})
	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	case "text":
		printTextReport(rep)
	default:
		return fmt.Errorf("unknown --output %q", *output)
	}
	if !rep.OK {
		// Nonzero exit when prerequisites fail, per issue #1.
		os.Exit(1)
	}
	return nil
}

func printTextReport(rep check.Report) {
	fmt.Printf("Kubeflock cluster check: context=%q namespace=%q\n", rep.Context, rep.Namespace)
	nOk := 0
	for _, c := range rep.Checks {
		mark := "ok"
		if !c.OK {
			if c.Advisory {
				mark = "warn"
			} else {
				mark = "FAIL"
			}
		}
		fmt.Printf("  [%s] %s: %s\n", mark, c.Name, c.Message)
		if !c.OK && c.Remediation != "" {
			fmt.Printf("         fix: %s\n", c.Remediation)
		}
		if c.OK {
			nOk++
		}
		if c.Category != "" && !c.OK {
			fmt.Printf("         category: %s\n", c.Category)
		}
	}
	if rep.OK {
		fmt.Printf("PASS: %d/%d checks passed\n", nOk, len(rep.Checks))
	} else {
		fmt.Printf("FAIL: %d/%d checks passed; fix the FAIL rows and rerun\n", nOk, len(rep.Checks))
	}
}

func validateContext(kubectlBin, kubeconfig, want string) error {
	args := []string{"config", "get-contexts", "-o", "name"}
	runner := kubectl.Runner{KubectlPath: kubectlBin, Kubeconfig: kubeconfig, TermGrace: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := runner.Run(ctx, args...)
	if err != nil {
		// Never print raw helper output; it may contain login URLs.
		msg := check.SanitizeLines(stdoutOrStderr(out, err))
		return fmt.Errorf("could not read kubeconfig contexts: %s", firstLine(msg))
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == want {
			return nil
		}
	}
	return fmt.Errorf("context %q not found in kubeconfig; list with: kubectl config get-contexts", want)
}

func stdoutOrStderr(out string, err error) string {
	if strings.TrimSpace(out) != "" {
		return out
	}
	if ke, ok := err.(*kubectl.Error); ok && ke != nil {
		return ke.Stderr
	}
	return err.Error()
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func defaultKubectl() string {
	if p := os.Getenv("KUBEFLOCK_KUBECTL"); p != "" {
		return p
	}
	return "kubectl"
}
