package kubeflock

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckoutProjectProtectsRemoteAndLocalWork(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "source")
	runGit(t, "init", "-b", "main", work)
	mustWrite(t, filepath.Join(work, "branch.txt"), "main\n", 0o600)
	runGit(t, "-C", work, "add", "branch.txt")
	runGit(t, "-C", work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "main")
	runGit(t, "-C", work, "checkout", "-b", "feature")
	mustWrite(t, filepath.Join(work, "branch.txt"), "feature\n", 0o600)
	runGit(t, "-C", work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-am", "feature")

	bare := filepath.Join(root, "source.git")
	runGit(t, "clone", "--bare", work, bare)
	kubectl := helperWrapper(t, root, "kubectl")
	t.Setenv("GO_WANT_KUBEFLOCK_HELPER", "1")
	remoteHome := filepath.Join(root, "remote")
	if err := os.Mkdir(remoteHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SANDBOX_HOME", remoteHome)
	local := filepath.Join(root, "local")
	if err := os.Mkdir(local, 0o700); err != nil {
		t.Fatal(err)
	}
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(local); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWorkingDirectory) })

	target := KubeTarget{Context: "test", Namespace: "dev"}
	sandbox := resolvedSandbox{Pod: "sandbox-pod", Container: "sandbox"}
	options := createOptions{Timeout: time.Minute, Global: globalOptions{Kubectl: kubectl}}
	if err := checkoutProject(context.Background(), target, sandbox, projectRequest{Repository: bare, Branch: "feature"}, options); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(remoteHome, "project")
	contents, err := os.ReadFile(filepath.Join(project, "branch.txt"))
	if err != nil || string(contents) != "feature\n" {
		t.Fatalf("feature checkout = %q, %v", contents, err)
	}
	mustWrite(t, filepath.Join(project, "branch.txt"), "dirty\n", 0o600)
	if err := checkoutProject(context.Background(), target, sandbox, projectRequest{Repository: bare}, options); err == nil {
		t.Fatal("retry overwrote an existing checkout")
	}
	contents, err = os.ReadFile(filepath.Join(project, "branch.txt"))
	if err != nil || string(contents) != "dirty\n" {
		t.Fatalf("dirty checkout changed to %q, %v", contents, err)
	}
	if _, err := os.Stat(filepath.Join(local, "project")); !os.IsNotExist(err) {
		t.Fatalf("local working directory was changed: %v", err)
	}
}

func TestCheckoutProjectRetriesFailuresAndUsesRemoteCredentials(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "source")
	runGit(t, "init", "-b", "main", work)
	mustWrite(t, filepath.Join(work, "README"), "private\n", 0o600)
	runGit(t, "-C", work, "add", "README")
	runGit(t, "-C", work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "initial")

	kubectl := helperWrapper(t, root, "kubectl")
	t.Setenv("GO_WANT_KUBEFLOCK_HELPER", "1")
	remoteHome := filepath.Join(root, "remote")
	if err := os.Mkdir(remoteHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SANDBOX_HOME", remoteHome)
	options := createOptions{Timeout: time.Minute, Global: globalOptions{Kubectl: kubectl}}
	target := KubeTarget{Context: "test", Namespace: "dev"}
	sandbox := resolvedSandbox{Pod: "sandbox-pod", Container: "sandbox"}

	missing := filepath.Join(root, "missing.git")
	request := projectRequest{Repository: missing}
	if err := checkoutProject(context.Background(), target, sandbox, request, options); err == nil {
		t.Fatal("missing repository checkout succeeded")
	}
	runGit(t, "clone", "--bare", work, missing)
	if err := checkoutProject(context.Background(), target, sandbox, request, options); err != nil {
		t.Fatalf("retry after clone failure: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(remoteHome, "project")); err != nil {
		t.Fatal(err)
	}

	privateRoot := filepath.Join(root, "http")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	privateRepo := filepath.Join(privateRoot, "private.git")
	runGit(t, "clone", "--bare", work, privateRepo)
	runGit(t, "--git-dir", privateRepo, "update-server-info")
	files := http.FileServer(http.Dir(privateRoot))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		user, password, ok := request.BasicAuth()
		if !ok || user != "agent" || password != "approved" {
			response.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		files.ServeHTTP(response, request)
	}))
	defer server.Close()
	privateRequest := projectRequest{Repository: server.URL + "/private.git"}
	if err := checkoutProject(context.Background(), target, sandbox, privateRequest, options); err == nil {
		t.Fatal("private checkout succeeded without sandbox credentials")
	}
	credential := strings.Replace(server.URL, "http://", "http://agent:approved@", 1)
	mustWrite(t, filepath.Join(remoteHome, ".git-credentials"), credential+"\n", 0o600)
	mustWrite(t, filepath.Join(remoteHome, ".gitconfig"), "[credential]\n\thelper = store\n", 0o600)
	if err := checkoutProject(context.Background(), target, sandbox, privateRequest, options); err != nil {
		t.Fatalf("private checkout with sandbox credentials: %v", err)
	}
}

func TestValidateCreationRejectsCredentialURLsAndBranchWithoutRepository(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "id")
	mustWrite(t, identity, "key\n", 0o600)
	for _, test := range []struct {
		name    string
		project projectRequest
		want    string
	}{
		{name: "credentials", project: projectRequest{Repository: "https://agent:secret@example.test/repo.git"}, want: "must not contain credentials"},
		{name: "query", project: projectRequest{Repository: "https://example.test/repo.git?token=secret"}, want: "must not contain credentials"},
		{name: "branch only", project: projectRequest{Branch: "feature"}, want: "requires --repository"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateCreation("sandbox", createOptions{Template: "dev-small", IdentityFile: identity, Project: &test.project})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateCreation error = %v", err)
			}
			if strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("validation error leaked credentials: %v", err)
			}
		})
	}
}

func runGit(t *testing.T, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}
