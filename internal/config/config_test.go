package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeflock", "config.yaml")
	cfg := Config{Context: "homelab", Namespace: "kubeflock-check"}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != cfg {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, cfg)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		cfg Config
		ok  bool
	}{
		{Config{"a", "b"}, true},
		{Config{"", "b"}, false},
		{Config{"a", ""}, false},
		{Config{"a", "Bad_NS"}, false},
		{Config{"a", "UPPER"}, false},
	}
	for i, c := range cases {
		err := c.cfg.Validate()
		if c.ok && err != nil {
			t.Errorf("case %d: want ok, got %v", i, err)
		}
		if !c.ok && err == nil {
			t.Errorf("case %d: want error, got nil", i)
		}
	}
}

func TestDefaultPathPrecedence(t *testing.T) {
	t.Setenv("KUBEFLOCK_CONFIG", "/tmp/custom.yaml")
	if got := DefaultPath(); got != "/tmp/custom.yaml" {
		t.Fatalf("env override: got %q", got)
	}
	if err := os.Unsetenv("KUBEFLOCK_CONFIG"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	want := filepath.Join("/tmp/xdg", "kubeflock", "config.yaml")
	if got := DefaultPath(); got != want {
		t.Fatalf("xdg: got %q want %q", got, want)
	}
}
