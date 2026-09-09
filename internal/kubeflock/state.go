package kubeflock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/renameio/v2"
)

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return renameio.WriteFile(path, data, mode, renameio.WithPermissions(mode))
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode %q: %w", path, err)
	}
	return nil
}

func managedSandboxDir(dir string) string { return filepath.Join(dir, "sandboxes") }
func managedSandboxPath(dir, uid string) string {
	return filepath.Join(managedSandboxDir(dir), uid+".json")
}

func validateConnection(connection Connection) error {
	if connection.Version != 1 || (connection.Phase != "prepared" && connection.Phase != "connected") {
		return errors.New("invalid connection version or phase")
	}
	if connection.Phase == "connected" && connection.ProfileID == "" {
		return errors.New("connected state requires profileId")
	}
	if connection.Sandbox.Context == "" || connection.Sandbox.Namespace == "" || connection.Sandbox.Name == "" || connection.Sandbox.UID == "" {
		return errors.New("connection contains an incomplete sandbox identity")
	}
	if connection.SSH.Alias == "" || connection.SSH.IdentityFile == "" || connection.SSH.KnownHostsFile == "" || connection.SSH.EntryFile == "" || connection.SSH.ProxyFile == "" || connection.SSH.ConfigFile == "" || connection.SSH.HostKey == "" {
		return errors.New("connection contains incomplete SSH state")
	}
	return nil
}

func loadConnection(path string) (Connection, error) {
	var connection Connection
	if err := loadJSON(path, &connection); err != nil {
		return Connection{}, err
	}
	return connection, validateConnection(connection)
}

func listConnections(dir string) ([]savedConnection, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []savedConnection
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		connection, err := loadConnection(path)
		if err != nil {
			return nil, err
		}
		out = append(out, savedConnection{File: path, Connection: connection})
	}
	slices.SortFunc(out, func(a, b savedConnection) int { return strings.Compare(a.File, b.File) })
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
	if sandbox.Claim.Context == "" || sandbox.Claim.Namespace == "" || sandbox.Claim.Name == "" || sandbox.Claim.UID == "" || sandbox.Template == "" || sandbox.WarmPool == "" || sandbox.IdentityFile == "" {
		return errors.New("managed sandbox contains incomplete identity")
	}
	if sandbox.Phase == "bound" && (sandbox.Sandbox == nil || sandbox.Home == nil) {
		return errors.New("bound sandbox requires sandbox and home identities")
	}
	return nil
}

func listManagedSandboxes(stateDir string) ([]savedSandbox, error) {
	dir := managedSandboxDir(stateDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []savedSandbox
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		var sandbox ManagedSandbox
		if err := loadJSON(path, &sandbox); err != nil {
			return nil, err
		}
		if err := validateManaged(sandbox); err != nil {
			return nil, fmt.Errorf("decode %q: %w", path, err)
		}
		out = append(out, savedSandbox{File: path, Sandbox: sandbox})
	}
	slices.SortFunc(out, func(a, b savedSandbox) int { return strings.Compare(a.File, b.File) })
	return out, nil
}

type savedSandbox struct {
	File    string
	Sandbox ManagedSandbox
}
