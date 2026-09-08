package check

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LoriKarikari/kubeflock/internal/config"
	"github.com/LoriKarikari/kubeflock/internal/kubectl"
)

// fakeKubectl writes a shell script emulating read-only kubectl responses.
// It logs every argv line to logPath and enforces --context EXPECTED_CONTEXT
// when that env var is set. DENY_SUBSTR, when set, makes matching
// `auth can-i` probes answer "no".
func fakeKubectl(t *testing.T, dir, logPath string) string {
	t.Helper()
	script := `#!/bin/sh
LOG="` + logPath + `"
printf '%s\n' "$*" >> "$LOG"
# Enforce explicit context when expected.
if [ -n "$EXPECTED_CONTEXT" ]; then
  case "$*" in
    *"config get-contexts"*) ;;
    *"--context $EXPECTED_CONTEXT"*) ;;
    *) echo "wrong context: $* (want $EXPECTED_CONTEXT)" >&2; exit 1 ;;
  esac
fi
case "$*" in
  *"api-versions"*)
    echo "v1"; echo "agents.x-k8s.io/v1beta1"; echo "extensions.agents.x-k8s.io/v1beta1"; exit 0 ;;
  *"auth can-i"*)
    if [ -n "$DENY_SUBSTR" ]; then
      case "$*" in *"$DENY_SUBSTR"*) echo "no"; exit 0 ;; esac
    fi
    if [ -n "$DENY_ALL" ]; then echo "no"; exit 0; fi
    echo "yes"; exit 0 ;;
  *"api-resources"*"extensions.agents.x-k8s.io"*)
    echo "sandboxclaims"; echo "sandboxtemplates"; echo "sandboxwarmpools"; exit 0 ;;
  *"api-resources"*"agents.x-k8s.io"*)
    echo "sandboxes"; exit 0 ;;
  *"get runtimeclass"*)
    echo '{"metadata":{"name":"gvisor"},"handler":"runsc"}'; exit 0 ;;
  *"get storageclass"*)
    echo '{"items":[{"metadata":{"name":"longhorn","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"driver.longhorn.io"}]}'; exit 0 ;;
  *"get namespace"*)
    echo '{"metadata":{"name":"ns"}}'; exit 0 ;;
  *"get resourcequota"*)
    echo '{"items":[{"metadata":{"name":"quota"}}]}'; exit 0 ;;
  *"get limitrange"*)
    echo '{"items":[{}]}'; exit 0 ;;
  *"config get-contexts"*)
    echo "saved"; echo "other"; exit 0 ;;
esac
echo "unexpected kubectl call: $*" >&2; exit 1
`
	p := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func runWithFake(t *testing.T, env map[string]string) (Report, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	bin := fakeKubectl(t, dir, logPath)
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg := config.Config{Context: "saved", Namespace: "dev-ns"}
	t.Setenv("EXPECTED_CONTEXT", "saved")
	rep := Run(context.Background(), cfg, Options{
		Runner:         kubectl.Runner{KubectlPath: bin, TermGrace: 100 * time.Millisecond},
		RequestTimeout: 2 * time.Second,
		Now:            func() time.Time { return time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC) },
	})
	data, _ := os.ReadFile(logPath)
	return rep, string(data)
}

// Explicit-context mismatch: the saved context pins the target even when the
// kubeconfig current-context points elsewhere. The fake rejects any call
// without --context saved, so a pass proves no reliance on current-context.
func TestExplicitContextMismatch(t *testing.T) {
	rep, log := runWithFake(t, nil)
	if !rep.OK {
		t.Fatalf("want OK, got %+v", rep)
	}
	if !strings.Contains(log, "--context saved") {
		t.Fatalf("missing explicit --context in calls:\n%s", log)
	}
	if strings.Contains(log, "--context other") {
		t.Fatalf("used wrong context:\n%s", log)
	}
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) < 5 {
		t.Fatalf("too few kubectl calls (%d), check incomplete", len(lines))
	}
}

// Insufficient permissions surface as denied with actionable remediation.
func TestInsufficientPermissions(t *testing.T) {
	rep, _ := runWithFake(t, map[string]string{"DENY_ALL": "1"})
	if rep.OK {
		t.Fatalf("want FAIL with denied permissions, got OK")
	}
	foundDenied := false
	for _, c := range rep.Checks {
		if !c.OK && c.Category == string(CategoryDenied) {
			foundDenied = true
			if c.Remediation == "" {
				t.Errorf("denied check %q lacks remediation", c.Name)
			}
		}
		if strings.Contains(c.Message, "Bearer") || strings.Contains(c.Message, "eyJ") {
			t.Errorf("possible credential leak in %q: %q", c.Name, c.Message)
		}
	}
	if !foundDenied {
		t.Fatalf("no denied check found: %+v", rep.Checks)
	}
}

// The check must perform no cluster writes: every kubectl top-level
// subcommand is read-only. `auth can-i create/delete ...` probes are queries
// (ephemeral SelfSubjectAccessReview), not persisted writes.
func TestNoClusterWrites(t *testing.T) {
	_, log := runWithFake(t, nil)
	allowed := map[string]bool{"api-versions": true, "api-resources": true, "get": true, "auth": true, "config": true}
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		fields := strings.Fields(line)
		// Strip global flags (--context X, -n NS, --request-timeout Xs).
		sub := ""
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			if f == "--context" || f == "-n" || f == "--request-timeout" {
				i++
				continue
			}
			if strings.HasPrefix(f, "-") {
				continue
			}
			sub = f
			break
		}
		if !allowed[sub] {
			t.Errorf("non-read subcommand %q in: %q", sub, line)
		}
		// Top-level mutating verbs are never allowed outside `auth can-i`.
		if (sub == "create" || sub == "delete" || sub == "patch" || sub == "apply" || sub == "replace") && !strings.Contains(line, "can-i") {
			t.Errorf("cluster write detected: %q", line)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		stderr string
		timed  bool
		want   Category
	}{
		{"Error from server (Forbidden): sandboxes is forbidden", false, CategoryDenied},
		{"Unauthorized: ID token expired", false, CategoryAuthExpired},
		{"Unable to connect to the server: dial tcp: connection refused", false, CategoryConnectivity},
		{"error: context \"x\" not found", false, CategoryConfig},
		{`runtimeclasses.node.k8s.io "gvisor" not found`, false, CategoryMissing},
		{"", true, CategoryTimeout},
		{"something strange", false, CategoryUnknown},
	}
	for i, c := range cases {
		if got := Classify(c.stderr, c.timed); got != c.want {
			t.Errorf("case %d: got %q want %q", i, got, c.want)
		}
	}
}

func TestSanitizeRedactsCredentials(t *testing.T) {
	in := "Bearer abc.def.ghi token\n" +
		"access_token=secret123\n" +
		"login https://example.com/authorize?code=supersecret&state=x\n" +
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-part-here"
	out := SanitizeLines(in)
	if strings.Contains(out, "supersecret") || strings.Contains(out, "secret123") {
		t.Fatalf("credentials leaked: %q", out)
	}
	if strings.Contains(out, "eyJhbGci") {
		t.Fatalf("JWT leaked: %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("want redaction marker, got %q", out)
	}
}
