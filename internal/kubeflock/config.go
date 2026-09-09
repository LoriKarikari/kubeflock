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
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return KubeTarget{}, fmt.Errorf("parse kubeflock config %q: %w", path, err)
	}
	target, err := configTarget(&doc)
	if err != nil {
		return KubeTarget{}, fmt.Errorf("invalid kubeflock config %q: %w", path, err)
	}
	return target, nil
}

func configTarget(doc *yaml.Node) (KubeTarget, error) {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	invalid := errors.New("config must contain string context and namespace")
	if doc.Kind != yaml.MappingNode {
		return KubeTarget{}, invalid
	}
	fields := make(map[string]string, 2)
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if key.Tag != "!!str" || value.Tag != "!!str" {
			return KubeTarget{}, invalid
		}
		fields[key.Value] = value.Value
	}
	target := KubeTarget{Context: fields["context"], Namespace: fields["namespace"]}
	if len(fields) != 2 || target.Context == "" || target.Namespace == "" {
		return KubeTarget{}, invalid
	}
	return target, validateTarget(target)
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
