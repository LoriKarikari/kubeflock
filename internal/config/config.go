package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config records the explicitly selected Kubernetes target for Kubeflock.
// Changing kubectl's current context never retargets Kubeflock; every
// cluster operation must pass cfg.Context explicitly to kubectl.
type Config struct {
	Context   string `yaml:"context"`
	Namespace string `yaml:"namespace"`
}

var namespaceRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// DefaultPath returns the shared config file used by both the CLI and the
// Herdr action so both interfaces see the same target.
//
// Precedence: KUBEFLOCK_CONFIG env, then XDG_CONFIG_HOME/kubeflock/config.yaml,
// then ~/.config/kubeflock/config.yaml.
func DefaultPath() string {
	if p := os.Getenv("KUBEFLOCK_CONFIG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "kubeflock-config.yaml"
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "kubeflock", "config.yaml")
}

// Load reads and validates the config at path.
func Load(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read kubeflock config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse kubeflock config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid kubeflock config %q: %w", path, err)
	}
	return cfg, nil
}

// Save validates then writes cfg to path with mode 0600.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode kubeflock config: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write kubeflock config %q: %w", path, err)
	}
	return nil
}

// Validate rejects empty or malformed context/namespace values.
func (c Config) Validate() error {
	if c.Context == "" {
		return errors.New("context is required")
	}
	if c.Namespace == "" {
		return errors.New("namespace is required")
	}
	if len(c.Namespace) > 63 || !namespaceRe.MatchString(c.Namespace) {
		return fmt.Errorf("namespace %q must be a DNS-1123 label", c.Namespace)
	}
	return nil
}
