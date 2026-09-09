package kubeflock

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type herdrMachine struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Target   string `json:"target"`
	Session  string `json:"session"`
	Enabled  bool   `json:"enabled"`
	Selected bool   `json:"selected"`
}

type connectOptions struct {
	Name, ExpectedUID, IdentityFile string
	Global                          globalOptions
}

func (a *App) runHerdr(ctx context.Context, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return runCaptured(callCtx, cmp.Or(os.Getenv("KUBEFLOCK_HERDR"), os.Getenv("HERDR_BIN_PATH"), "herdr"), args, nil, nil)
}

func (a *App) listMachines(ctx context.Context) ([]herdrMachine, error) {
	out, err := a.runHerdr(ctx, "machine", "list", "--json")
	if err != nil {
		return nil, err
	}
	var machines []herdrMachine
	if err := json.Unmarshal([]byte(out), &machines); err != nil {
		return nil, errors.New("invalid Herdr machine list")
	}
	for _, machine := range machines {
		if machine.ID == "" || machine.Label == "" || machine.Target == "" || machine.Session == "" {
			return nil, errors.New("invalid Herdr machine")
		}
	}
	return machines, nil
}

func owns(machine herdrMachine, connection Connection) bool {
	return machine.Label == connection.Herdr.Label && machine.Target == connection.SSH.Alias && machine.Session == connection.Herdr.Session
}

func (a *App) ensureMachine(ctx context.Context, connection Connection) (string, error) {
	machines, err := a.listMachines(ctx)
	if err != nil {
		return "", err
	}
	if connection.Phase == "connected" {
		for _, machine := range machines {
			if machine.ID != connection.ProfileID {
				continue
			}
			if !owns(machine, connection) {
				return "", fmt.Errorf("saved Herdr profile %s is missing or no longer matches its identity", connection.ProfileID)
			}
			if !machine.Enabled {
				_, err = a.runHerdr(ctx, "machine", "enable", machine.ID)
			}
			return machine.ID, err
		}
		return "", fmt.Errorf("saved Herdr profile %s is missing or no longer matches its identity", connection.ProfileID)
	}
	matches := matchingMachines(machines, connection)
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple Herdr profiles match %s", connection.SSH.Alias)
	}
	if len(matches) == 0 {
		if _, err := a.runHerdr(ctx, "machine", "add", connection.SSH.Alias, "--label", connection.Herdr.Label, "--remote-session", connection.Herdr.Session); err != nil {
			return "", fmt.Errorf("herdr exited: %w", err)
		}
		machines, err = a.listMachines(ctx)
		if err != nil {
			return "", err
		}
		matches = matchingMachines(machines, connection)
	}
	if len(matches) != 1 {
		return "", errors.New("machine add succeeded without saving the Kubeflock profile")
	}
	if !matches[0].Enabled {
		_, err = a.runHerdr(ctx, "machine", "enable", matches[0].ID)
	}
	return matches[0].ID, err
}

func matchingMachines(machines []herdrMachine, connection Connection) []herdrMachine {
	matches := []herdrMachine{}
	for _, machine := range machines {
		if owns(machine, connection) {
			matches = append(matches, machine)
		}
	}
	return matches
}

func (a *App) disableMachine(ctx context.Context, connection Connection) error {
	if connection.Phase != "connected" {
		return nil
	}
	machines, err := a.listMachines(ctx)
	if err != nil {
		return err
	}
	for _, machine := range machines {
		if machine.ID != connection.ProfileID {
			continue
		}
		if !owns(machine, connection) {
			return fmt.Errorf("refusing to disable non-Kubeflock profile %s", connection.ProfileID)
		}
		if machine.Enabled {
			_, err = a.runHerdr(ctx, "machine", "disable", machine.ID)
		}
		return err
	}
	return nil
}

func selectConnection(target *KubeTarget, stateDir, name string) (*savedConnection, error) {
	connections, err := listConnections(stateDir)
	if err != nil {
		return nil, err
	}
	matches := []savedConnection{}
	for _, saved := range connections {
		connection := saved.Connection
		if target != nil && (connection.Sandbox.Context != target.Context || connection.Sandbox.Namespace != target.Namespace) {
			continue
		}
		if name != "" && connection.Sandbox.Name != name {
			continue
		}
		matches = append(matches, saved)
	}
	if len(matches) > 1 {
		return nil, errors.New("multiple saved sandboxes match; specify a sandbox name")
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return &matches[0], nil
}

func (a *App) connect(ctx context.Context, target KubeTarget, options connectOptions) (Connection, error) {
	saved, err := selectConnection(&target, options.Global.StateDir, options.Name)
	if err != nil {
		return Connection{}, err
	}
	if saved == nil && options.Name == "" {
		return Connection{}, errors.New("specify a sandbox name for the first connection")
	}
	if saved == nil && options.IdentityFile == "" {
		return Connection{}, errors.New("specify --identity for the first connection")
	}
	if saved != nil && options.IdentityFile != "" {
		identity, err := filepath.Abs(options.IdentityFile)
		if err != nil {
			return Connection{}, err
		}
		if identity != saved.Connection.SSH.IdentityFile {
			return Connection{}, errors.New("the saved connection uses a different SSH identity file")
		}
	}
	name, expectedUID := options.Name, options.ExpectedUID
	kubeconfig, kubectl := options.Global.Kubeconfig, options.Global.Kubectl
	if saved != nil {
		name, expectedUID = saved.Connection.Sandbox.Name, saved.Connection.Sandbox.UID
		if saved.Connection.Kubeconfig != nil {
			kubeconfig = *saved.Connection.Kubeconfig
		}
		kubectl = saved.Connection.Kubectl
	}
	client, err := newKubeClient(ctx, target, kubeconfig)
	if err != nil {
		return Connection{}, err
	}
	resolved, err := client.resolveSandbox(ctx, target, name, expectedUID)
	if err != nil {
		return Connection{}, err
	}
	pinCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pinArgs := []string{"--context", target.Context, "--namespace", target.Namespace, "exec", resolved.Pod, "-c", resolved.Container, "--", "cat", "/home/agent/.ssh/ssh_host_ed25519_key.pub"}
	currentPinRaw, err := a.runKubectl(pinCtx, globalOptions{Kubeconfig: kubeconfig, Kubectl: kubectl}, pinArgs...)
	if err != nil {
		return Connection{}, fmt.Errorf("kubectl exec failed: %s", commandDetail(err))
	}
	currentPin, err := normalizeHostKey(currentPinRaw)
	if err != nil {
		return Connection{}, err
	}
	var path string
	var connection Connection
	if saved != nil {
		path, connection = saved.File, saved.Connection
	} else {
		identity, err := filepath.EvalSymlinks(options.IdentityFile)
		if err != nil {
			return Connection{}, err
		}
		identity, err = filepath.Abs(identity)
		if err != nil {
			return Connection{}, err
		}
		if _, err := os.Stat(identity); err != nil {
			return Connection{}, err
		}
		uid := resolved.Identity.UID
		sshDir := filepath.Join(filepath.Dir(options.Global.StateDir), "ssh")
		configFile := os.Getenv("KUBEFLOCK_SSH_CONFIG")
		if configFile == "" {
			home, _ := os.UserHomeDir()
			configFile = filepath.Join(home, ".ssh", "config")
		}
		kubeconfigValue := (*string)(nil)
		if options.Global.Kubeconfig != "" {
			value := options.Global.Kubeconfig
			kubeconfigValue = &value
		}
		connection = Connection{Version: 1, Phase: "prepared", Sandbox: resolved.Identity, SSH: SSHState{Alias: "kubeflock-" + uid, IdentityFile: identity, KnownHostsFile: filepath.Join(sshDir, uid+".known_hosts"), EntryFile: filepath.Join(sshDir, uid+".conf"), ProxyFile: filepath.Join(sshDir, uid+"-proxy"), ConfigFile: configFile, HostKey: currentPin}, Herdr: HerdrState{Label: fmt.Sprintf("Kubeflock: %s [%s]", name, truncate(uid, 8)), Session: "agent"}, Kubeconfig: kubeconfigValue, Kubectl: kubectl}
		path = filepath.Join(options.Global.StateDir, uid+".json")
		if err := saveJSON(path, connection); err != nil {
			return Connection{}, err
		}
	}
	if currentPin != connection.SSH.HostKey {
		return Connection{}, fmt.Errorf("SSH host key mismatch for sandbox %s/%s; refusing to replace the saved pin", target.Namespace, name)
	}
	if err := ensureSSHFiles(connection, path); err != nil {
		return Connection{}, err
	}
	profileID, err := a.ensureMachine(ctx, connection)
	if err != nil {
		return Connection{}, err
	}
	if connection.Phase == "connected" {
		return connection, nil
	}
	connection.Phase, connection.ProfileID = "connected", profileID
	if err := saveJSON(path, connection); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func (a *App) disconnect(ctx context.Context, name, stateDir string) (Connection, error) {
	saved, err := selectConnection(nil, stateDir, name)
	if err != nil {
		return Connection{}, err
	}
	if saved == nil {
		return Connection{}, errors.New("no saved Kubeflock connection matches this target")
	}
	if err := a.disableMachine(ctx, saved.Connection); err != nil {
		return Connection{}, err
	}
	return saved.Connection, nil
}

func normalizeHostKey(raw string) (string, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || key.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("sandbox returned an invalid Ed25519 host key")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}

func sshQuote(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
func shellQuote(value string) string { return `'` + strings.ReplaceAll(value, `'`, `'"'"'`) + `'` }

func ensureSSHFiles(connection Connection, stateFile string) error {
	state := connection.SSH
	main, err := os.ReadFile(state.ConfigFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(state.ConfigFile); statErr == nil {
		mode = info.Mode().Perm()
	}
	include := "Include " + sshQuote(state.EntryFile)
	included := false
	for line := range strings.SplitSeq(string(main), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == include || trimmed == "Include "+state.EntryFile {
			included = true
		}
	}
	if !included {
		if err := atomicWrite(state.ConfigFile, []byte(include+"\n"+string(main)), mode); err != nil {
			return err
		}
	}
	if err := atomicWrite(state.KnownHostsFile, []byte(state.Alias+" "+state.HostKey+"\n"), 0o600); err != nil {
		return err
	}
	entry := fmt.Sprintf("Host %s\n  HostName %s\n  User agent\n  IdentityFile %s\n  UserKnownHostsFile %s\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  ProxyCommand %s\n", state.Alias, state.Alias, sshQuote(state.IdentityFile), sshQuote(state.KnownHostsFile), sshQuote(state.ProxyFile))
	if err := atomicWrite(state.EntryFile, []byte(entry), 0o600); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	proxy := "#!/bin/sh\nexec " + shellQuote(executable) + " sandbox proxy --state " + shellQuote(stateFile) + "\n"
	return atomicWrite(state.ProxyFile, []byte(proxy), 0o700)
}

func (a *App) runProxy(ctx context.Context, stateFile string) (int, error) {
	connection, err := loadConnection(stateFile)
	if err != nil {
		return 0, err
	}
	target := KubeTarget{Context: connection.Sandbox.Context, Namespace: connection.Sandbox.Namespace}
	kubeconfig := ""
	if connection.Kubeconfig != nil {
		kubeconfig = *connection.Kubeconfig
	}
	client, err := newKubeClient(ctx, target, kubeconfig)
	if err != nil {
		return 0, err
	}
	resolved, err := client.resolveSandbox(ctx, target, connection.Sandbox.Name, connection.Sandbox.UID)
	if err != nil {
		return 0, err
	}
	args := []string{"--context", target.Context, "--namespace", target.Namespace, "exec", "-i", resolved.Pod, "-c", resolved.Container, "--", "socat", "STDIO", fmt.Sprintf("TCP:127.0.0.1:%d", resolved.SSHPort)}
	if kubeconfig != "" {
		args = append([]string{"--kubeconfig", kubeconfig}, args...)
	}
	return relay(ctx, connection.Kubectl, args, a.In, a.Out, a.Err)
}
