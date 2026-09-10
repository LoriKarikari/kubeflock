package kubeflock

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const credentialConfigName = "kubeflock-credentials"

type credentialReference struct {
	Name        string `json:"-"`
	Secret      string `json:"secret"`
	Key         string `json:"key"`
	Environment string `json:"environment"`
}

type credential struct {
	Reference credentialReference
	Value     []byte
}

func (k *kubeClient) credentialReferences(ctx context.Context, namespace string) ([]credentialReference, error) {
	config, err := k.core.ConfigMaps(namespace).Get(ctx, credentialConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read approved credential choices: %w", err)
	}
	credentials := make([]credentialReference, 0, len(config.Data))
	environments := map[string]string{}
	for name, raw := range config.Data {
		var reference credentialReference
		if err := json.Unmarshal([]byte(raw), &reference, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("approved credential %q has invalid configuration", name)
		}
		reference.Name = name
		if len(validation.IsDNS1123Label(name)) != 0 || len(validation.IsDNS1123Label(reference.Secret)) != 0 || reference.Key == "" || !validEnvironmentName(reference.Environment) {
			return nil, fmt.Errorf("approved credential %q has invalid configuration", name)
		}
		if existing := environments[reference.Environment]; existing != "" {
			return nil, fmt.Errorf("approved credentials %q and %q export the same environment variable", existing, name)
		}
		environments[reference.Environment] = name
		credentials = append(credentials, reference)
	}
	slices.SortFunc(credentials, func(a, b credentialReference) int { return strings.Compare(a.Name, b.Name) })
	return credentials, nil
}

func validEnvironmentName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z')) {
		return false
	}
	for _, character := range name[1:] {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func (k *kubeClient) resolveCredentials(ctx context.Context, namespace string, selected []string) ([]credential, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	references, err := k.credentialReferences(ctx, namespace)
	if err != nil {
		return nil, err
	}
	credentials := make([]credential, 0, len(selected))
	seen := map[string]bool{}
	for _, name := range selected {
		if seen[name] {
			return nil, fmt.Errorf("credential %q was selected more than once", name)
		}
		seen[name] = true
		index := slices.IndexFunc(references, func(reference credentialReference) bool { return reference.Name == name })
		if index < 0 {
			return nil, fmt.Errorf("credential %q is not approved; list choices with: kubeflock sandbox credential list", name)
		}
		reference := references[index]
		secret, err := k.core.Secrets(namespace).Get(ctx, reference.Secret, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read approved credential %q from Secret %s/%s: %w", name, namespace, reference.Secret, err)
		}
		value, ok := secret.Data[reference.Key]
		if !ok {
			return nil, fmt.Errorf("approved credential %q is missing key %q in Secret %s/%s", name, reference.Key, namespace, reference.Secret)
		}
		if bytes.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("approved credential %q contains a NUL byte and cannot be exported as an environment variable", name)
		}
		credentials = append(credentials, credential{Reference: reference, Value: value})
	}
	return credentials, nil
}

func installCredentials(ctx context.Context, target KubeTarget, sandbox resolvedSandbox, credentials []credential, options globalOptions) error {
	if len(credentials) == 0 {
		return nil
	}
	archive, err := credentialArchive(credentials)
	if err != nil {
		return err
	}
	args := []string{
		"--context", target.Context, "--namespace", target.Namespace,
		"exec", "-i", sandbox.Pod, "-c", sandbox.Container, "--", "sh", "-c",
		`set -eu; mkdir -p "$HOME/.config/kubeflock/credentials"; tar -xm -C "$HOME"; touch "$HOME/.bashrc"; line='. "$HOME/.config/kubeflock/credentials/env.sh"'; grep -qxF "$line" "$HOME/.bashrc" || printf '%s\n' "$line" >> "$HOME/.bashrc"`,
	}
	if _, err := runKubectlInput(ctx, options, archive, args...); err != nil {
		return fmt.Errorf("install approved credentials in sandbox %s: %w", sandbox.Identity.Name, err)
	}
	return nil
}

func credentialArchive(credentials []credential) (io.Reader, error) {
	var buffer bytes.Buffer
	archive := tar.NewWriter(&buffer)
	var environment strings.Builder
	for _, item := range credentials {
		path := ".config/kubeflock/credentials/" + item.Reference.Name
		if err := archive.WriteHeader(&tar.Header{Name: path, Mode: 0o600, Size: int64(len(item.Value))}); err != nil {
			return nil, err
		}
		if _, err := archive.Write(item.Value); err != nil {
			return nil, err
		}
		fmt.Fprintf(&environment, "export %s=\"$(cat \"$HOME/%s\")\"\n", item.Reference.Environment, path)
	}
	script := []byte(environment.String())
	if err := archive.WriteHeader(&tar.Header{Name: ".config/kubeflock/credentials/env.sh", Mode: 0o600, Size: int64(len(script))}); err != nil {
		return nil, err
	}
	if _, err := archive.Write(script); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buffer.Bytes()), nil
}

func sameCredentials(saved, selected []string) error {
	if slices.Equal(saved, selected) {
		return nil
	}
	return errors.New("saved sandbox uses a different credential selection")
}
