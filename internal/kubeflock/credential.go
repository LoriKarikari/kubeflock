package kubeflock

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const credentialConfigName = "kubeflock-credentials"

type credentialConfig struct {
	Secret      string `json:"secret"`
	Key         string `json:"key"`
	Environment string `json:"environment"`
}

type credentialReference struct {
	Name   string
	Config credentialConfig
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
	references := make([]credentialReference, 0, len(config.Data))
	environments := map[string]string{}
	for name, raw := range config.Data {
		var decoded credentialConfig
		if err := json.Unmarshal([]byte(raw), &decoded, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("approved credential %q has invalid configuration: %w", name, err)
		}
		if len(validation.IsDNS1123Label(name)) != 0 || len(validation.IsDNS1123Label(decoded.Secret)) != 0 || decoded.Key == "" || !validEnvironmentName(decoded.Environment) {
			return nil, fmt.Errorf("approved credential %q has invalid configuration", name)
		}
		if existing := environments[decoded.Environment]; existing != "" {
			return nil, fmt.Errorf("approved credentials %q and %q export the same environment variable", existing, name)
		}
		environments[decoded.Environment] = name
		references = append(references, credentialReference{Name: name, Config: decoded})
	}
	slices.SortFunc(references, func(a, b credentialReference) int { return strings.Compare(a.Name, b.Name) })
	return references, nil
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

func (k *kubeClient) selectCredentials(ctx context.Context, namespace string, selected []string) ([]credentialReference, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	references, err := k.credentialReferences(ctx, namespace)
	if err != nil {
		return nil, err
	}
	selectedReferences := make([]credentialReference, 0, len(selected))
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
		selectedReferences = append(selectedReferences, references[index])
	}
	return selectedReferences, nil
}

func (k *kubeClient) readCredentials(ctx context.Context, namespace string, references []credentialReference) ([]credential, error) {
	credentials := make([]credential, 0, len(references))
	for _, reference := range references {
		secret, err := k.core.Secrets(namespace).Get(ctx, reference.Config.Secret, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read approved credential %q from Secret %s/%s: %w", reference.Name, namespace, reference.Config.Secret, err)
		}
		value, ok := secret.Data[reference.Config.Key]
		if !ok {
			return nil, fmt.Errorf("approved credential %q is missing key %q in Secret %s/%s", reference.Name, reference.Config.Key, namespace, reference.Config.Secret)
		}
		if bytes.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("approved credential %q contains a NUL byte and cannot be exported as an environment variable", reference.Name)
		}
		credentials = append(credentials, credential{Reference: reference, Value: value})
	}
	return credentials, nil
}

func installCredentials(ctx context.Context, target KubeTarget, sandbox resolvedSandbox, credentials []credential, options createOptions) error {
	if len(credentials) == 0 {
		return nil
	}
	archive, err := credentialArchive(credentials)
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	args := []string{
		"--context", target.Context, "--namespace", target.Namespace,
		"exec", "-i", sandbox.Pod, "-c", sandbox.Container, "--", "sh", "-c",
		`set -eu; mkdir -p "$HOME/.config/kubeflock/credentials"; tar -xm -C "$HOME"; touch "$HOME/.bashrc"; line='. "$HOME/.config/kubeflock/credentials/env.sh"'; grep -qxF "$line" "$HOME/.bashrc" || printf '%s\n' "$line" >> "$HOME/.bashrc"`,
	}
	if _, err := runKubectlInput(callCtx, options.Global, archive, args...); err != nil {
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
		fmt.Fprintf(&environment, "export %s=\"$(cat \"$HOME/%s\")\"\n", item.Reference.Config.Environment, path)
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

func sameCredentials(first, second []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(first)), slices.Sorted(slices.Values(second)))
}
