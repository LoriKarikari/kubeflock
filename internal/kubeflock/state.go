package kubeflock

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
)

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return renameio.WriteFile(path, data, mode, renameio.WithPermissions(mode))
}

func saveJSON(path string, value any) error {
	data, err := json.Marshal(value, jsontext.WithIndent("  "), json.Deterministic(true))
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o600)
}

func loadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode %q: %w", path, err)
	}
	return nil
}

func managedSandboxDir(dir string) string { return filepath.Join(dir, "sandboxes") }
func managedSandboxPath(dir, uid string) string {
	return filepath.Join(managedSandboxDir(dir), uid+".json")
}
func retainedHomeDir(dir string) string { return filepath.Join(dir, "retained-homes") }
func retainedHomePath(dir, uid string) string {
	return filepath.Join(retainedHomeDir(dir), uid+".json")
}

func validateConnection(connection Connection) error {
	if connection.Version != 1 || (connection.Phase != "prepared" && connection.Phase != "connected") {
		return errors.New("invalid connection version or phase")
	}
	if connection.Phase == "connected" && connection.ProfileID == "" {
		return errors.New("connected state requires profileId")
	}
	if !connection.Sandbox.complete() {
		return errors.New("connection contains an incomplete sandbox identity")
	}
	if !connection.SSH.complete() {
		return errors.New("connection contains incomplete SSH state")
	}
	if err := validateSSHState(connection.SSH); err != nil {
		return err
	}
	return nil
}

func stateFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	return paths, nil
}

func loadState[T any](path string, validate func(T) error) (T, error) {
	var value T
	if err := loadJSON(path, &value); err != nil {
		return value, err
	}
	if err := validate(value); err != nil {
		return value, fmt.Errorf("decode %q: %w", path, err)
	}
	return value, nil
}

func loadConnection(path string) (Connection, error) { return loadState(path, validateConnection) }

func listConnections(dir string) ([]savedConnection, error) {
	paths, err := stateFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []savedConnection
	for _, path := range paths {
		connection, err := loadConnection(path)
		if err != nil {
			return nil, err
		}
		out = append(out, savedConnection{File: path, Connection: connection})
	}
	return out, nil
}

type savedConnection struct {
	File       string
	Connection Connection
}

func validateManaged(sandbox ManagedSandbox) error {
	if sandbox.Version != 1 || (sandbox.Phase != "claimed" && sandbox.Phase != "bound") {
		return errors.New("invalid managed sandbox version or phase")
	}
	if !sandbox.Claim.complete() || sandbox.Template == "" || sandbox.WarmPool == "" || sandbox.IdentityFile == "" {
		return errors.New("managed sandbox contains incomplete identity")
	}
	if sandbox.Phase == "bound" && (sandbox.Sandbox == nil || sandbox.Home == nil) {
		return errors.New("bound sandbox requires sandbox and home identities")
	}
	return nil
}

func listManagedSandboxes(stateDir string) ([]ManagedSandbox, error) {
	paths, err := stateFiles(managedSandboxDir(stateDir))
	if err != nil {
		return nil, err
	}
	var out []ManagedSandbox
	for _, path := range paths {
		sandbox, err := loadState(path, validateManaged)
		if err != nil {
			return nil, err
		}
		out = append(out, sandbox)
	}
	return out, nil
}

func validateRetainedHome(retained RetainedHome) error {
	if retained.Version != 1 || (retained.State != retainedHomeAvailable && retained.State != retainedHomeRestoring && retained.State != retainedHomeDeleting) {
		return errors.New("invalid retained home version or state")
	}
	if retained.Template == "" || retained.WarmPool == "" || !retained.Origin.complete() {
		return errors.New("retained home contains incomplete provenance")
	}
	if retained.Home.Name == "" || retained.Home.UID == "" || retained.Home.Capacity == "" {
		return errors.New("retained home contains incomplete storage identity")
	}
	if retained.State == retainedHomeDeleting && (retained.Deletion == nil || retained.Deletion.Name == "" || retained.Deletion.UID == "" || retained.Deletion.ReclaimPolicy == "") {
		return errors.New("deleting retained home requires persistent volume identity")
	}
	if retained.State != retainedHomeDeleting && retained.Deletion != nil {
		return errors.New("persistent volume deletion identity requires deleting state")
	}
	return nil
}

func selectRetainedHome(target KubeTarget, uid, stateDir string) (*RetainedHome, error) {
	homes, err := listRetainedHomes(stateDir)
	if err != nil {
		return nil, err
	}
	for i := range homes {
		if homes[i].Home.UID != uid {
			continue
		}
		if homes[i].Origin.Context != target.Context || homes[i].Origin.Namespace != target.Namespace {
			return nil, fmt.Errorf("retained home %s belongs to target %s/%s", uid, homes[i].Origin.Context, homes[i].Origin.Namespace)
		}
		return &homes[i], nil
	}
	return nil, fmt.Errorf("no retained home has UID %s", uid)
}

func retainedHomeForOrigin(target KubeTarget, name, stateDir string) (*RetainedHome, error) {
	homes, err := listRetainedHomes(stateDir)
	if err != nil {
		return nil, err
	}
	for i := range homes {
		origin := homes[i].Origin
		if origin.Context == target.Context && origin.Namespace == target.Namespace && origin.Name == name {
			return &homes[i], nil
		}
	}
	return nil, nil
}

func listRetainedHomes(stateDir string) ([]RetainedHome, error) {
	paths, err := stateFiles(retainedHomeDir(stateDir))
	if err != nil {
		return nil, err
	}
	var out []RetainedHome
	for _, path := range paths {
		home, err := loadState(path, validateRetainedHome)
		if err != nil {
			return nil, err
		}
		out = append(out, home)
	}
	return out, nil
}
