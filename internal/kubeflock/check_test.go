package kubeflock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeCheckKubectl(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "kubectl")
	body := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CHECK_LOG"
case "$*" in
  *"api-versions"*)
    if [ -n "$ALPHA_ONLY" ]; then printf 'v1\nagents.x-k8s.io/v1alpha1\nextensions.agents.x-k8s.io/v1alpha1\n'; else printf 'v1\nagents.x-k8s.io/v1beta1\nextensions.agents.x-k8s.io/v1beta1\n'; fi ;;
  *"auth can-i"*) if [ -n "$DENY_ALL" ]; then echo no; exit 1; else echo yes; fi ;;
  *"api-resources"*"extensions.agents.x-k8s.io"*) printf 'sandboxclaims\nsandboxtemplates\nsandboxwarmpools\n' ;;
  *"api-resources"*"agents.x-k8s.io"*) echo sandboxes ;;
  *"get runtimeclass"*)
    if [ -n "$TOKEN_LEAK" ]; then echo 'access_token="REPORT_TOKEN_XYZ"' >&2; exit 1; fi
    echo '{"metadata":{"name":"gvisor"},"handler":"runsc"}' ;;
  *"get storageclass"*) echo '{"items":[{"metadata":{"name":"longhorn","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}]}' ;;
  *"get namespace"*) echo '{"metadata":{"name":"dev"}}' ;;
  *"get resourcequota"*)
    if [ -n "$CONFIGMAP_ONLY" ]; then echo '{"items":[{"metadata":{"name":"thin"},"spec":{"hard":{"count/configmaps":"5"}}}]}'; else echo '{"items":[{"metadata":{"name":"quota"},"spec":{"hard":{"pods":"1","requests.cpu":"1","requests.storage":"1Gi"}}}]}'; fi ;;
  *"get limitrange"*) echo '{"items":[{}]}' ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, log
}

func TestClusterCheckUsesPinnedContextAndReadOnlyPermissions(t *testing.T) {
	kubectl, log := fakeCheckKubectl(t)
	t.Setenv("FAKE_CHECK_LOG", log)
	app := NewApp(strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	app.Now = func() time.Time { return time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC) }
	report := app.runCheck(context.Background(), KubeTarget{Context: "saved", Namespace: "dev"}, globalOptions{Kubectl: kubectl}, 2*time.Second)
	if !report.OK {
		t.Fatalf("report = %#v", report.Checks)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(calls)), "\n") {
		if !strings.Contains(line, "--context saved") {
			t.Fatalf("call omitted saved context: %s", line)
		}
		if strings.Contains(line, "auth can-i delete") || strings.Contains(line, "auth can-i patch") || strings.Contains(line, "auth can-i get secrets") {
			t.Fatalf("unexpected permission: %s", line)
		}
	}
	if !strings.Contains(string(calls), "auth can-i create pods --subresource=exec") {
		t.Fatalf("missing pod exec permission probe: %s", calls)
	}
}

func TestClusterCheckClassifiesFailuresAndRedactsCredentials(t *testing.T) {
	kubectl, _ := fakeCheckKubectl(t)
	for _, test := range []struct {
		env      string
		check    string
		category string
	}{{"DENY_ALL", "perm-get-sandboxes", "denied"}, {"ALPHA_ONLY", "agents-api", "missing-infrastructure"}, {"CONFIGMAP_ONLY", "budgets-quota", "missing-infrastructure"}} {
		t.Run(test.env, func(t *testing.T) {
			t.Setenv(test.env, "1")
			report := NewApp(strings.NewReader(""), &strings.Builder{}, &strings.Builder{}).runCheck(context.Background(), KubeTarget{Context: "saved", Namespace: "dev"}, globalOptions{Kubectl: kubectl}, time.Second)
			result := findCheck(report.Checks, test.check)
			if result == nil || result.OK || result.Category != test.category {
				t.Fatalf("%s = %#v", test.check, result)
			}
		})
	}
	t.Run("redaction", func(t *testing.T) {
		t.Setenv("TOKEN_LEAK", "1")
		report := NewApp(strings.NewReader(""), &strings.Builder{}, &strings.Builder{}).runCheck(context.Background(), KubeTarget{Context: "saved", Namespace: "dev"}, globalOptions{Kubectl: kubectl}, time.Second)
		for _, check := range report.Checks {
			if strings.Contains(check.Message, "REPORT_TOKEN_XYZ") {
				t.Fatal("credential leaked into report")
			}
		}
	})
}

func findCheck(checks []CheckResult, name string) *CheckResult {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}
