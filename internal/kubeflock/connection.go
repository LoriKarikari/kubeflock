package kubeflock

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

type herdrMachine struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Target  string `json:"target"`
	Session string `json:"session"`
	Enabled bool   `json:"enabled"`
}

type connectOptions struct {
	Name         string
	Label        string
	ExpectedUID  string
	IdentityFile string
	Global       globalOptions
}

func runHerdr(ctx context.Context, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := runCaptured(callCtx, cmp.Or(os.Getenv("KUBEFLOCK_HERDR"), os.Getenv("HERDR_BIN_PATH"), "herdr"), args, nil, nil)
	if detail := stderrDetail(err); detail != "" {
		err = fmt.Errorf("%w: %s", err, detail)
	}
	return out, err
}

func listMachines(ctx context.Context) ([]herdrMachine, error) {
	out, err := runHerdr(ctx, "machine", "list", "--json")
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

func (c Connection) owns(machine herdrMachine) bool {
	return machine.Label == c.Herdr.Label &&
		machine.Target == c.SSH.Alias &&
		machine.Session == c.Herdr.Session
}

func ensureMachine(ctx context.Context, connection Connection) (string, error) {
	machines, err := listMachines(ctx)
	if err != nil {
		return "", err
	}
	if connection.Phase == connectionConnected {
		return ensureSavedMachine(ctx, machines, connection)
	}
	matches := matchingMachines(machines, connection)
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple Herdr profiles match %s", connection.SSH.Alias)
	}
	if len(matches) == 0 {
		if _, err := runHerdr(
			ctx,
			"machine", "add", connection.SSH.Alias,
			"--label", connection.Herdr.Label,
			"--remote-session", connection.Herdr.Session,
		); err != nil {
			return "", fmt.Errorf("herdr exited: %w", err)
		}
		machines, err = listMachines(ctx)
		if err != nil {
			return "", err
		}
		matches = matchingMachines(machines, connection)
	}
	if len(matches) != 1 {
		return "", errors.New("machine add succeeded without saving the Kubeflock profile")
	}
	if !matches[0].Enabled {
		_, err = runHerdr(ctx, "machine", "enable", matches[0].ID)
	}
	return matches[0].ID, err
}

func ensureSavedMachine(ctx context.Context, machines []herdrMachine, connection Connection) (string, error) {
	for _, machine := range machines {
		if machine.ID != connection.ProfileID {
			continue
		}
		if !connection.owns(machine) {
			break
		}
		if !machine.Enabled {
			_, err := runHerdr(ctx, "machine", "enable", machine.ID)
			return machine.ID, err
		}
		return machine.ID, nil
	}
	return "", fmt.Errorf("saved Herdr profile %s is missing or no longer matches its identity", connection.ProfileID)
}

func matchingMachines(machines []herdrMachine, connection Connection) []herdrMachine {
	matches := make([]herdrMachine, 0, 1)
	for _, machine := range machines {
		if connection.owns(machine) {
			matches = append(matches, machine)
		}
	}
	return matches
}

func disableMachine(ctx context.Context, saved *savedConnection) error {
	if saved == nil || saved.Connection.Phase != connectionConnected {
		return nil
	}
	connection := saved.Connection
	machines, err := listMachines(ctx)
	if err != nil {
		return err
	}
	for _, machine := range machines {
		if machine.ID != connection.ProfileID {
			continue
		}
		if !connection.owns(machine) {
			return fmt.Errorf("refusing to disable non-Kubeflock profile %s", connection.ProfileID)
		}
		if machine.Enabled {
			_, err = runHerdr(ctx, "machine", "disable", machine.ID)
		}
		return err
	}
	return nil
}

func removeConnection(ctx context.Context, saved *savedConnection) error {
	if saved == nil {
		return nil
	}
	connection := saved.Connection
	if connection.Phase == connectionConnected {
		machines, err := listMachines(ctx)
		if err != nil {
			return err
		}
		for _, machine := range machines {
			if machine.ID != connection.ProfileID {
				continue
			}
			if !connection.owns(machine) {
				return fmt.Errorf("refusing to remove non-Kubeflock profile %s", connection.ProfileID)
			}
			if _, err := runHerdr(ctx, "machine", "remove", machine.ID); err != nil {
				return err
			}
			break
		}
	}
	if err := removeSSHInclude(connection.SSH); err != nil {
		return err
	}
	return removeStateFiles(saved)
}

func removeStateFiles(saved *savedConnection) error {
	stateDir := filepath.Dir(saved.File)
	sshDir := filepath.Join(filepath.Dir(stateDir), "ssh")
	paths := []string{saved.Connection.SSH.KnownHostsFile, saved.Connection.SSH.EntryFile, saved.Connection.SSH.ProxyFile, saved.File}
	for _, path := range paths {
		if !pathWithin(path, stateDir) && !pathWithin(path, sshDir) {
			return fmt.Errorf("refusing to remove %s because it is outside the Kubeflock state directory", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func pathWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func removeSSHInclude(state SSHState) error {
	configPath, err := sshConfigPath(state.ConfigFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	include, bare := "Include "+sshQuote(state.EntryFile), "Include "+state.EntryFile
	removed := false
	lines := strings.SplitAfter(string(data), "\n")
	lines = slices.DeleteFunc(lines, func(line string) bool {
		trimmed := strings.TrimSpace(line)
		if trimmed == include || trimmed == bare {
			removed = true
			return true
		}
		return false
	})
	if !removed {
		return nil
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(configPath); statErr == nil {
		mode = info.Mode().Perm()
	}
	return atomicWrite(configPath, []byte(strings.Join(lines, "")), mode)
}

func selectConnection(target *KubeTarget, stateDir, name string) (*savedConnection, error) {
	connections, err := listConnections(stateDir)
	if err != nil {
		return nil, err
	}
	var match *savedConnection
	for i := range connections {
		sandbox := connections[i].Connection.Sandbox
		if target != nil && (sandbox.Context != target.Context || sandbox.Namespace != target.Namespace) {
			continue
		}
		if name != "" && sandbox.Name != name {
			continue
		}
		if match != nil {
			return nil, errors.New("multiple saved sandboxes match; specify a sandbox name")
		}
		match = &connections[i]
	}
	return match, nil
}

func connect(ctx context.Context, target KubeTarget, options connectOptions) (Connection, error) {
	saved, err := selectConnection(&target, options.Global.StateDir, options.Name)
	if err != nil {
		return Connection{}, err
	}
	if err := validateSavedConnection(saved, options); err != nil {
		return Connection{}, err
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
	pinArgs := []string{
		"--context", target.Context,
		"--namespace", target.Namespace,
		"exec", resolved.Pod,
		"-c", resolved.Container,
		"--", "cat", "/home/agent/.ssh/ssh_host_ed25519_key.pub",
	}
	currentPinRaw, err := runKubectl(pinCtx, globalOptions{Kubeconfig: kubeconfig, Kubectl: kubectl}, pinArgs...)
	if err != nil {
		return Connection{}, fmt.Errorf("kubectl exec: %w", err)
	}
	currentPin, err := normalizeHostKey(currentPinRaw)
	if err != nil {
		return Connection{}, err
	}
	return activateConnection(ctx, target, options, saved, resolved.Identity, kubectl, currentPin)
}

func validateSavedConnection(saved *savedConnection, options connectOptions) error {
	if saved == nil && options.Name == "" {
		return errors.New("specify a sandbox name for the first connection")
	}
	if saved == nil && options.IdentityFile == "" {
		return errors.New("specify --identity for the first connection")
	}
	return adoptIdentity(saved, options)
}

// adoptIdentity records a new identity file on a connection that never reached the connected
// phase. A connected sandbox keeps its identity so a later command cannot switch keys silently.
func adoptIdentity(saved *savedConnection, options connectOptions) error {
	if saved == nil || options.IdentityFile == "" {
		return nil
	}
	identity, err := resolveIdentityFile(options.IdentityFile)
	if err != nil {
		return err
	}
	if identity == saved.Connection.SSH.IdentityFile {
		return nil
	}
	if saved.Connection.Phase == connectionConnected {
		return errors.New("the saved connection uses a different SSH identity file")
	}
	saved.Connection.SSH.IdentityFile = identity
	return saveJSON(saved.File, saved.Connection)
}

// resolveIdentityFile returns the absolute path of a usable SSH identity file.
func resolveIdentityFile(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func activateConnection(ctx context.Context, target KubeTarget, options connectOptions, saved *savedConnection, sandbox SandboxIdentity, kubectl, hostKey string) (Connection, error) {
	var path string
	var connection Connection
	var err error
	if saved != nil {
		path, connection = saved.File, saved.Connection
	} else {
		path, connection, err = prepareConnection(options, sandbox, kubectl, hostKey)
		if err != nil {
			return Connection{}, err
		}
	}
	if hostKey != connection.SSH.HostKey {
		return Connection{}, fmt.Errorf("SSH host key mismatch for sandbox %s/%s; refusing to replace the saved pin", target.Namespace, sandbox.Name)
	}
	if err := ensureSSHFiles(connection, path); err != nil {
		return Connection{}, err
	}
	profileID, err := ensureMachine(ctx, connection)
	if err != nil {
		return Connection{}, err
	}
	if connection.Phase == connectionConnected {
		return connection, nil
	}
	connection.Phase, connection.ProfileID = connectionConnected, profileID
	if err := saveJSON(path, connection); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func prepareConnection(options connectOptions, sandbox SandboxIdentity, kubectl, hostKey string) (string, Connection, error) {
	identity, err := resolveIdentityFile(options.IdentityFile)
	if err != nil {
		return "", Connection{}, err
	}
	uid := sandbox.UID
	sshDir := filepath.Join(filepath.Dir(options.Global.StateDir), "ssh")
	configFile := os.Getenv("KUBEFLOCK_SSH_CONFIG")
	if configFile == "" {
		home, _ := os.UserHomeDir()
		configFile = filepath.Join(home, ".ssh", "config")
	}
	var kubeconfig *string
	if options.Global.Kubeconfig != "" {
		kubeconfig = &options.Global.Kubeconfig
	}
	connection := Connection{
		Version:    1,
		Phase:      "prepared",
		Sandbox:    sandbox,
		Kubeconfig: kubeconfig,
		Kubectl:    kubectl,
		SSH: SSHState{
			Alias:          "kubeflock-" + uid,
			IdentityFile:   identity,
			KnownHostsFile: filepath.Join(sshDir, uid+".known_hosts"),
			EntryFile:      filepath.Join(sshDir, uid+".conf"),
			ProxyFile:      filepath.Join(sshDir, uid+"-proxy"),
			ConfigFile:     configFile,
			HostKey:        hostKey,
		},
		Herdr: HerdrState{
			Label:   cmp.Or(options.Label, sandbox.Name),
			Session: "agent",
		},
	}
	path := filepath.Join(options.Global.StateDir, uid+".json")
	if err := validateSSHState(connection.SSH); err != nil {
		return "", Connection{}, err
	}
	return path, connection, saveJSON(path, connection)
}

func disconnect(ctx context.Context, target *KubeTarget, name, stateDir string) (Connection, error) {
	saved, err := selectConnection(target, stateDir, name)
	if err != nil {
		return Connection{}, err
	}
	if saved == nil {
		return Connection{}, errors.New("no saved Kubeflock connection matches this target")
	}
	if err := disableMachine(ctx, saved); err != nil {
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

func validateSSHState(state SSHState) error {
	fields := []struct{ name, value string }{
		{"alias", state.Alias},
		{"identity file", state.IdentityFile},
		{"known hosts file", state.KnownHostsFile},
		{"entry file", state.EntryFile},
		{"proxy file", state.ProxyFile},
		{"config file", state.ConfigFile},
	}
	for _, field := range fields {
		if !utf8.ValidString(field.value) || strings.ContainsAny(field.value, "\r\n\x00") {
			return fmt.Errorf("saved SSH %s %q contains an invalid character", field.name, field.value)
		}
	}
	return nil
}

func sshConfigPath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}
func shellQuote(value string) string { return `'` + strings.ReplaceAll(value, `'`, `'"'"'`) + `'` }

func ensureSSHFiles(connection Connection, stateFile string) error {
	state := connection.SSH
	if err := validateSSHState(state); err != nil {
		return err
	}
	configPath, err := sshConfigPath(state.ConfigFile)
	if err != nil {
		return err
	}
	main, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(configPath); statErr == nil {
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
		if err := atomicWrite(configPath, []byte(include+"\n"+string(main)), mode); err != nil {
			return err
		}
	}
	if err := atomicWrite(state.KnownHostsFile, []byte(state.Alias+" "+state.HostKey+"\n"), 0o600); err != nil {
		return err
	}
	entry := fmt.Sprintf(
		"Host %s\n  HostName %s\n  User agent\n  IdentityFile %s\n  UserKnownHostsFile %s\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  ProxyCommand %s\n",
		state.Alias,
		state.Alias,
		sshQuote(state.IdentityFile),
		sshQuote(state.KnownHostsFile),
		sshQuote(state.ProxyFile),
	)
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
	args := []string{
		"--context", target.Context,
		"--namespace", target.Namespace,
		"exec", "-i", resolved.Pod,
		"-c", resolved.Container,
		"--", "socat", "STDIO", fmt.Sprintf("TCP:127.0.0.1:%d", resolved.SSHPort),
	}
	if kubeconfig != "" {
		args = append([]string{"--kubeconfig", kubeconfig}, args...)
	}
	return relay(ctx, connection.Kubectl, args, a.In, a.Out, a.Err)
}
