package kubeflock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
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
	var values map[string]any
	if err := yaml.UnmarshalStrict(data, &values); err != nil {
		return KubeTarget{}, fmt.Errorf("parse kubeflock config %q: %w", path, err)
	}
	contextName, contextOK := values["context"].(string)
	namespace, namespaceOK := values["namespace"].(string)
	if !contextOK || !namespaceOK || len(values) != 2 {
		return KubeTarget{}, fmt.Errorf("invalid kubeflock config %q: config must contain string context and namespace", path)
	}
	target := KubeTarget{Context: contextName, Namespace: namespace}
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
