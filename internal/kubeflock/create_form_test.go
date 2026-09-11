package kubeflock

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/huh"
)

func TestCreateFormValidation(t *testing.T) {
	for _, name := range []string{"", "Uppercase", "-agent", "agent-", strings.Repeat("a", 64)} {
		if err := validateFormName(name); err == nil {
			t.Errorf("accepted invalid sandbox name %q", name)
		}
	}
	if err := validateFormName("agent-1"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := filepath.Join(home, "identity")
	if err := os.WriteFile(key, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := formIdentity("~/identity")
	if err != nil || resolved != key {
		t.Fatalf("identity = %q, %v; want %q", resolved, err, key)
	}
	for _, path := range []string{"", home, filepath.Join(home, "missing")} {
		if _, err := formIdentity(path); err == nil {
			t.Errorf("accepted invalid identity path %q", path)
		}
	}
}

func TestCreateFormEscapeDoesNotConfirm(t *testing.T) {
	var values createForm
	var output bytes.Buffer
	app := NewApp(strings.NewReader("\x1b"), &output, &output)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	form := sandboxCreateForm(KubeTarget{Context: "test", Namespace: "developer"}, []string{"starter"}, &values)
	if err := app.runPopupForm(ctx, form); !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("Escape returned %v, want user abort", err)
	}
	if values.Confirmed {
		t.Fatal("cancelled form confirmed creation")
	}
}
