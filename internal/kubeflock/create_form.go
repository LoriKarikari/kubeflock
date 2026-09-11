package kubeflock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type createForm struct {
	Name      string
	Template  string
	Identity  string
	Confirmed bool
}

func sandboxCreateForm(target KubeTarget, templates []string, values *createForm) *huh.Form {
	choices := make([]huh.Option[string], 0, len(templates))
	for _, name := range templates {
		choices = append(choices, huh.NewOption(name, name))
	}
	return huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Sandbox name").Placeholder("my-agent").
			Description("Lowercase letters, numbers, and hyphens; up to 63 characters.").
			Value(&values.Name).Validate(validateFormName),
		huh.NewSelect[string]().Title("Template").
			Description("From configured warm pools. Security checks run before creation.").
			Options(choices...).Height(4).Value(&values.Template),
		huh.NewInput().Title("SSH identity file").Placeholder("~/.ssh/id_ed25519").
			Description("Private key on this workstation; never copied to the sandbox.").
			Value(&values.Identity).Validate(func(value string) error {
			_, err := formIdentity(value)
			return err
		}),
		huh.NewConfirm().Title("Create sandbox and connect to Herdr?").
			Description("Allocates compute and persistent storage. Charges may apply.").
			Affirmative("Create").Negative("Cancel").Value(&values.Confirmed),
	).Title("Create sandbox").Description(fmt.Sprintf("Context: %s\nNamespace: %s\nTab to move between fields. Escape to cancel.", target.Context, target.Namespace)))
}

func validateFormName(value string) error {
	if len(validation.IsDNS1123Label(value)) != 0 {
		return errors.New("use 1-63 lowercase letters, numbers, or hyphens; start and end with a letter or number")
	}
	return nil
}

func formIdentity(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("choose a private SSH key file")
	}
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	path, err := resolveIdentityFile(value)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("SSH identity must be a regular file")
	}
	return path, nil
}

func (a *App) runPopupForm(ctx context.Context, form *huh.Form) error {
	keys := huh.NewDefaultKeyMap()
	keys.Quit.SetKeys("esc", "ctrl+c")
	keys.Quit.SetHelp("esc", "cancel")
	return form.WithInput(a.In).WithOutput(a.Out).WithKeyMap(keys).RunWithContext(ctx)
}

func (a *App) createPopup(ctx context.Context, options globalOptions) error {
	target, err := loadConfig(options.ConfigPath)
	if err != nil {
		return a.createPopupResult(ctx, "Cannot create sandbox", err.Error())
	}
	client, err := newKubeClient(ctx, target, options.Kubeconfig)
	if err != nil {
		return a.createPopupResult(ctx, "Cannot load templates", err.Error())
	}
	fmt.Fprintln(a.Out, "Loading templates from the selected cluster...")
	loadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	pools, err := client.extensions.SandboxWarmPools(target.Namespace).List(loadCtx, metav1.ListOptions{})
	cancel()
	if err != nil {
		return a.createPopupResult(ctx, "Cannot load templates", err.Error())
	}
	var templates []string
	for _, pool := range pools.Items {
		if pool.Spec.TemplateRef.Name != "" {
			templates = append(templates, pool.Spec.TemplateRef.Name)
		}
	}
	slices.Sort(templates)
	templates = slices.Compact(templates)
	if len(templates) == 0 {
		return a.createPopupResult(ctx, "No templates available", "Ask your cluster administrator to configure a sandbox template and warm pool in "+target.Namespace+".")
	}
	var values createForm
	if err := a.runPopupForm(ctx, sandboxCreateForm(target, templates, &values)); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil
		}
		return err
	}
	if !values.Confirmed {
		return nil
	}
	identity, err := formIdentity(values.Identity)
	if err != nil {
		return a.createPopupResult(ctx, "Invalid SSH identity", err.Error())
	}
	fmt.Fprintf(a.Out, "Creating %s in %s/%s...\nWaiting for readiness and Herdr connection, up to 5 minutes.\nClosing this popup does not delete allocated resources.\n", values.Name, target.Context, target.Namespace)
	created, err := createSandbox(ctx, target, values.Name, createOptions{
		Template: values.Template, IdentityFile: identity,
		Timeout: 5 * time.Minute, Poll: 2 * time.Second, Global: options,
	})
	if err != nil {
		return a.createPopupResult(ctx, "Creation did not complete", err.Error()+"\n\nResources may already exist. Retry with the same name, template, and SSH identity to recover. No automatic deletion was performed.")
	}
	return a.createPopupResult(ctx, "Sandbox ready", fmt.Sprintf("%s is connected to Herdr.\n\nHome: %s\nClosing this popup leaves the sandbox running.", created.Name, created.Home.Name))
}

func (a *App) createPopupResult(ctx context.Context, title, detail string) error {
	form := huh.NewForm(huh.NewGroup(huh.NewNote().Title(title).Description(detail).Next(true).NextLabel("Close")))
	if err := a.runPopupForm(ctx, form); err != nil && !errors.Is(err, huh.ErrUserAborted) {
		return err
	}
	return nil
}
