package kubeflock

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

func defaultConfigPath() string {
	if path := os.Getenv("KUBEFLOCK_CONFIG"); path != "" {
		return path
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "kubeflock", "config.yaml")
}

func defaultStateDir() string {
	if path := os.Getenv("KUBEFLOCK_STATE_DIR"); path != "" {
		return path
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "kubeflock", "connections")
}

func validateTarget(target KubeTarget) error {
	if target.Context == "" {
		return errors.New("context must be a non-empty string")
	}
	if target.Namespace == "" {
		return errors.New("namespace must be a non-empty string")
	}
	if len(validation.IsDNS1123Label(target.Namespace)) != 0 {
		return fmt.Errorf("namespace %q must be a DNS-1123 label", target.Namespace)
	}
	return nil
}

func loadConfig(path string) (KubeTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KubeTarget{}, fmt.Errorf("read kubeflock config %q: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var target KubeTarget
	if err := decoder.Decode(&target); err != nil {
		return KubeTarget{}, fmt.Errorf("parse kubeflock config %q: %w", path, err)
	}
	if err := validateTarget(target); err != nil {
		return KubeTarget{}, fmt.Errorf("invalid kubeflock config %q: %w", path, err)
	}
	return target, nil
}

func saveConfig(path string, target KubeTarget) error {
	if err := validateTarget(target); err != nil {
		return err
	}
	data, err := yaml.Marshal(target)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o600)
}

// loadSavedTarget returns the configured target, or nil when no config exists yet.
func loadSavedTarget(path string) (*KubeTarget, error) {
	target, err := loadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &target, nil
}
