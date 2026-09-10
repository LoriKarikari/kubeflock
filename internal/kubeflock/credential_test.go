package kubeflock

import (
	"archive/tar"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCredentialArchiveProtectsFilesAndExports(t *testing.T) {
	archive, err := credentialArchive([]credential{{
		Reference: credentialReference{Name: "provider", Config: credentialConfig{Environment: "APPROVED_TOKEN"}},
		Value:     []byte("value"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	modes := map[string]int64{}
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name], modes[header.Name] = string(body), header.Mode
	}
	if files[".config/kubeflock/credentials/provider"] != "value" {
		t.Fatalf("credential file = %#v", files)
	}
	if !strings.Contains(files[".config/kubeflock/credentials/env.sh"], `export APPROVED_TOKEN="$(cat "$HOME/.config/kubeflock/credentials/provider")"`) {
		t.Fatalf("environment script = %q", files[".config/kubeflock/credentials/env.sh"])
	}
	for name, mode := range modes {
		if mode != 0o600 {
			t.Fatalf("%s mode = %o", name, mode)
		}
	}
}

func TestSameCredentialsIgnoresOrder(t *testing.T) {
	if !sameCredentials([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("matching selections in a different order were rejected")
	}
	if !sameCredentials(nil, nil) {
		t.Fatal("empty selections did not match")
	}
	if sameCredentials([]string{"a"}, []string{"a", "b"}) || sameCredentials(nil, []string{"a"}) {
		t.Fatal("different selections matched")
	}
}
