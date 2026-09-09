package kubeflock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type fixtureClaim struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       struct {
		WarmPoolRef struct {
			Name string `json:"name"`
		} `json:"warmPoolRef"`
	} `json:"spec"`
	Status struct {
		Conditions []metav1.Condition `json:"conditions"`
		Sandbox    struct {
			Name string `json:"name"`
		} `json:"sandbox"`
	} `json:"status"`
}

type fixtureAPI struct {
	mu      sync.Mutex
	claims  map[string]fixtureClaim
	creates int
	reads   map[string]int
	methods []string
	auth    []string
}

func (f *fixtureAPI) snapshot() (int, map[string]int, map[string]fixtureClaim, []string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, maps.Clone(f.reads), maps.Clone(f.claims), slices.Clone(f.methods), slices.Clone(f.auth)
}

func (f *fixtureAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, request.Method)
	f.auth = append(f.auth, request.Header.Get("Authorization"))
	response.Header().Set("content-type", "application/json")
	path := request.URL.Path
	if strings.Contains(path, "/sandboxtemplates/") {
		_, name, _ := strings.CutLast(path, "/")
		writeFixture(response, templateFixture(name, name != "insecure"))
		return
	}
	if strings.HasSuffix(path, "/sandboxwarmpools") {
		writeFixture(response, map[string]any{
			"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
			"kind":       "SandboxWarmPoolList",
			"items": []any{
				poolFixture("dev-small"),
				poolFixture("insecure"),
			},
		})
		return
	}
	if strings.HasSuffix(path, "/sandboxclaims") && request.Method == http.MethodPost {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		metadata, ok := body["metadata"].(map[string]any)
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		spec, ok := body["spec"].(map[string]any)
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		ref, ok := spec["warmPoolRef"].(map[string]any)
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		name, ok := metadata["name"].(string)
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		pool, ok := ref["name"].(string)
		if !ok {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, exists := f.claims[name]; exists {
			response.WriteHeader(http.StatusConflict)
			writeFixture(response, map[string]string{"message": "already exists"})
			return
		}
		f.creates++
		claim := claimFixture(name, pool)
		if name != "delayed" && name != "waiting" {
			claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
			claim.Status.Sandbox.Name = name
		}
		f.claims[name] = claim
		response.WriteHeader(http.StatusCreated)
		writeFixture(response, claim)
		return
	}
	if strings.HasSuffix(path, "/sandboxclaims") {
		items := []fixtureClaim{}
		if field := request.URL.Query().Get("fieldSelector"); field != "" {
			name := strings.TrimPrefix(field, "metadata.name=")
			if claim, ok := f.claims[name]; ok {
				f.reads[name]++
				if name == "delayed" && f.reads[name] >= 2 {
					claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
					claim.Status.Sandbox.Name = name
					f.claims[name] = claim
				}
				items = append(items, claim)
			}
		} else {
			for _, claim := range f.claims {
				if claim.Metadata.Labels[managedByLabel] == managedByValue {
					items = append(items, claim)
				}
			}
		}
		writeFixture(response, map[string]any{"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaimList", "items": items})
		return
	}
	if strings.Contains(path, "/sandboxes/") {
		_, name, _ := strings.CutLast(path, "/")
		writeFixture(response, map[string]any{
			"apiVersion": "agents.x-k8s.io/v1beta1",
			"kind":       "Sandbox",
			"metadata": map[string]any{
				"name":      name,
				"namespace": "dev",
				"uid":       "sandbox-" + name,
			},
			"status": map[string]any{
				"selector": "agents.x-k8s.io/sandbox=" + name,
				"conditions": []any{map[string]string{
					"type": "Ready", "status": "True",
				}},
			},
		})
		return
	}
	if strings.HasSuffix(path, "/pods") {
		name := strings.TrimPrefix(request.URL.Query().Get("labelSelector"), "agents.x-k8s.io/sandbox=")
		controller := true
		writeFixture(response, map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
			"items": []any{map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      name,
					"namespace": "dev",
					"ownerReferences": []any{map[string]any{
						"uid": "sandbox-" + name, "controller": controller,
					}},
				},
				"spec": map[string]any{
					"containers": []any{map[string]any{
						"name": "sandbox",
						"ports": []any{map[string]any{
							"name": "ssh", "containerPort": 2200,
						}},
					}},
				},
			}},
		})
		return
	}
	if strings.Contains(path, "/persistentvolumeclaims/home-") {
		_, name, _ := strings.CutLast(path, "/")
		sandbox := strings.TrimPrefix(name, "home-")
		controller := true
		writeFixture(response, map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      name,
				"namespace": "dev",
				"uid":       name + "-uid",
				"ownerReferences": []any{map[string]any{
					"uid": "sandbox-" + sandbox, "controller": controller,
				}},
			},
			"spec":   map[string]any{"storageClassName": "longhorn"},
			"status": map[string]any{"capacity": map[string]string{"storage": "10Gi"}},
		})
		return
	}
	response.WriteHeader(http.StatusNotFound)
	writeFixture(response, map[string]string{"message": "not found"})
}

func writeFixture(writer io.Writer, value any) { _ = json.NewEncoder(writer).Encode(value) }
func metadataFixture(name, uid string) map[string]any {
	return map[string]any{"name": name, "namespace": "dev", "uid": uid}
}

func poolFixture(template string) map[string]any {
	return map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
		"kind":       "SandboxWarmPool",
		"metadata":   metadataFixture(template+"-pool", template+"-pool-uid"),
		"spec": map[string]any{
			"replicas":           0,
			"sandboxTemplateRef": map[string]string{"name": template},
		},
	}
}

func claimFixture(name, pool string) fixtureClaim {
	claim := fixtureClaim{
		APIVersion: "extensions.agents.x-k8s.io/v1beta1",
		Kind:       "SandboxClaim",
		Metadata: metav1.ObjectMeta{
			Name:      name,
			Namespace: "dev",
			UID:       types.UID("claim-" + name),
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
	}
	claim.Spec.WarmPoolRef.Name = pool
	return claim
}

func templateFixture(name string, secure bool) map[string]any {
	runtimeClass := "gvisor"
	if !secure {
		runtimeClass = "runc"
	}

	podSecurity := map[string]any{
		"runAsNonRoot": true,
		"runAsUser":    1000,
		"runAsGroup":   1000,
		"fsGroup":      1000,
		"seccompProfile": map[string]string{
			"type": "RuntimeDefault",
		},
	}
	containerSecurity := map[string]any{
		"allowPrivilegeEscalation": false,
		"runAsNonRoot":             true,
		"runAsUser":                1000,
		"capabilities":             map[string]any{"drop": []string{"ALL"}},
		"seccompProfile":           map[string]string{"type": "RuntimeDefault"},
	}
	container := map[string]any{
		"securityContext": containerSecurity,
		"ports":           []any{map[string]any{"name": "ssh", "containerPort": 2200}},
		"resources": map[string]any{
			"requests": map[string]string{"cpu": "500m", "memory": "1Gi"},
			"limits":   map[string]string{"cpu": "2", "memory": "4Gi"},
		},
		"volumeMounts": []any{map[string]string{"name": "home", "mountPath": "/home/agent"}},
	}
	podSpec := map[string]any{
		"runtimeClassName":             runtimeClass,
		"automountServiceAccountToken": false,
		"securityContext":              podSecurity,
		"containers":                   []any{container},
		"volumes": []any{map[string]any{
			"name":                  "home",
			"persistentVolumeClaim": map[string]string{"claimName": "home"},
		}},
	}

	return map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
		"kind":       "SandboxTemplate",
		"metadata":   metadataFixture(name, name+"-uid"),
		"spec": map[string]any{
			"networkPolicyManagement": "Managed",
			"podTemplate":             map[string]any{"spec": podSpec},
			"volumeClaimTemplates": []any{map[string]any{
				"metadata": map[string]string{"name": "home"},
				"spec": map[string]any{
					"storageClassName": "longhorn",
					"resources": map[string]any{
						"requests": map[string]string{"storage": "10Gi"},
					},
				},
			}},
		},
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_KUBEFLOCK_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(2)
	}
	kind, args := os.Args[separator+1], os.Args[separator+2:]
	switch kind {
	case "credential":
		fmt.Print(`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"fixture"}}`)
	case "kubectl":
		helperKubectl(args)
	case "herdr":
		helperHerdr(args)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func helperKubectl(args []string) {
	if log := os.Getenv("FAKE_KUBECTL_LOG"); log != "" {
		file, _ := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		fmt.Fprintln(file, strings.Join(args, " "))
		file.Close()
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "ssh_host_ed25519_key.pub") {
		fmt.Println(os.Getenv("FAKE_HOST_KEY"))
		return
	}
	if strings.Contains(joined, "socat STDIO TCP:127.0.0.1:2200") {
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return
	}
	if joined == "config get-contexts -o name" {
		fmt.Println("test")
		return
	}
	os.Exit(2)
}

type herdrFixture struct {
	AddCount int            `json:"addCount"`
	Machines []herdrMachine `json:"machines"`
	PaneArgs []string       `json:"paneArgs,omitempty"`
}

func helperHerdr(args []string) {
	path := os.Getenv("FAKE_HERDR_STATE")
	data, _ := os.ReadFile(path)
	var state herdrFixture
	_ = json.Unmarshal(data, &state)
	save := func() { data, _ := json.Marshal(state); _ = os.WriteFile(path, data, 0o600) }
	joined := strings.Join(args, " ")
	if joined == "machine list --json" {
		writeFixture(os.Stdout, state.Machines)
		return
	}
	if len(args) >= 2 && args[0] == "machine" && args[1] == "add" {
		if os.Getenv("FAKE_HERDR_FAIL_ADD") == "1" {
			os.Exit(1)
		}
		state.AddCount++
		state.Machines = append(state.Machines, herdrMachine{ID: fmt.Sprintf("%032x", state.AddCount), Target: args[2], Label: valueAfter(args, "--label"), Session: valueAfter(args, "--remote-session"), Enabled: true})
		save()
		return
	}
	if len(args) == 3 && args[0] == "machine" && (args[1] == "enable" || args[1] == "disable") {
		for i := range state.Machines {
			if state.Machines[i].ID == args[2] {
				state.Machines[i].Enabled = args[1] == "enable"
				save()
				return
			}
		}
		os.Exit(1)
	}
	if strings.HasPrefix(joined, "plugin pane open ") {
		state.PaneArgs = args
		save()
		return
	}
	os.Exit(2)
}

func valueAfter(args []string, name string) string {
	index := slices.Index(args, name)
	if index >= 0 && index+1 < len(args) {
		return args[index+1]
	}
	return ""
}

func helperWrapper(t *testing.T, dir, kind string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, kind)
	body := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=TestHelperProcess -- %s \"$@\"\n", executable, kind)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildCLI(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "kubeflock")
	command := exec.Command("go", "build", "-o", path, "../../cmd/kubeflock")
	command.Env = append(os.Environ(), "GOTOOLCHAIN=go1.27.1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	return path
}

type result struct {
	status int
	stdout string
	stderr string
}

func invoke(t *testing.T, binary string, args, env []string, input string) result {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = append(os.Environ(), env...)
	command.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	status := 0
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		status = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{status, stdout.String(), stderr.String()}
}

func TestCLIConnectionAndSandboxLifecycle(t *testing.T) {
	dir := t.TempDir()
	api := &fixtureAPI{claims: map[string]fixtureClaim{}, reads: map[string]int{}}
	server := httptest.NewServer(api)
	defer server.Close()
	binary := buildCLI(t, dir)
	kubectl := helperWrapper(t, dir, "kubectl")
	herdr := helperWrapper(t, dir, "herdr")
	credential := helperWrapper(t, dir, "credential")
	config, kubeconfig := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "kubeconfig.yaml")
	stateDir, sshConfig := filepath.Join(dir, "state"), filepath.Join(dir, "ssh", "config")
	identity := filepath.Join(dir, "id_ed25519")
	herdrState, kubectlLog := filepath.Join(dir, "herdr.json"), filepath.Join(dir, "kubectl.log")
	mustWrite(t, config, "context: test\nnamespace: dev\n", 0o600)
	mustWrite(t, identity, "private key fixture\n", 0o600)
	mustWrite(t, sshConfig, "Host unrelated\n  HostName unrelated.example\n", 0o600)
	mustWrite(t, herdrState, `{"addCount":0,"machines":[{"id":"ffffffffffffffffffffffffffffffff","label":"Unrelated","target":"unrelated","session":"main","enabled":true,"selected":false}]}`, 0o600)
	mustWrite(t, kubeconfig, fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: test\n  cluster:\n    server: %s\n    insecure-skip-tls-verify: true\ncontexts:\n- name: test\n  context:\n    cluster: test\n    user: test\ncurrent-context: test\nusers:\n- name: test\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: %s\n      interactiveMode: Never\n", server.URL, credential), 0o600)
	env := []string{"GO_WANT_KUBEFLOCK_HELPER=1", "KUBEFLOCK_CONFIG=" + config, "KUBEFLOCK_STATE_DIR=" + stateDir, "KUBEFLOCK_KUBECTL=" + kubectl, "KUBEFLOCK_HERDR=" + herdr, "KUBEFLOCK_SSH_CONFIG=" + sshConfig, "FAKE_HERDR_STATE=" + herdrState, "FAKE_HOST_KEY=" + keyA, "FAKE_KUBECTL_LOG=" + kubectlLog}

	failed := invoke(t, binary, []string{"sandbox", "create", "delayed", "--template", "dev-small", "--identity", identity, "--timeout", "10s", "--kubeconfig", kubeconfig}, append(env, "FAKE_HERDR_FAIL_ADD=1"), "")
	if failed.status != 2 || !strings.Contains(failed.stderr, "herdr exited") {
		t.Fatalf("failed create = %#v", failed)
	}
	creates, reads, _, _, _ := api.snapshot()
	if creates != 1 || reads["delayed"] != 2 {
		t.Fatalf("creates=%d reads=%d", creates, reads["delayed"])
	}
	connectionFile := filepath.Join(stateDir, "sandbox-delayed.json")
	assertJSONField(t, connectionFile, "phase", "prepared")
	connected := invoke(t, binary, []string{"sandbox", "create", "delayed", "--template", "dev-small", "--identity", identity, "--timeout", "2s", "--kubeconfig", kubeconfig}, env, "")
	if connected.status != 0 || !strings.Contains(connected.stdout, "ready sandbox delayed") {
		t.Fatalf("connected = %#v", connected)
	}
	creates, _, _, _, _ = api.snapshot()
	if creates != 1 {
		t.Fatalf("duplicate created %d claims", creates)
	}
	assertJSONField(t, connectionFile, "phase", "connected")
	sshData, _ := os.ReadFile(sshConfig)
	if !strings.Contains(string(sshData), "Include ") || !strings.Contains(string(sshData), "Host unrelated") {
		t.Fatalf("SSH config lost content: %s", sshData)
	}
	proxy := filepath.Join(stateDir, "..", "ssh", "sandbox-delayed-proxy")
	proxied := invoke(t, proxy, nil, env, "through-api")
	if proxied.status != 0 || proxied.stdout != "through-api" {
		t.Fatalf("proxy = %#v", proxied)
	}
	log, _ := os.ReadFile(kubectlLog)
	if !strings.Contains(string(log), "TCP:127.0.0.1:2200") {
		t.Fatalf("proxy log = %s", log)
	}

	disconnected := invoke(t, binary, []string{"sandbox", "disconnect", "delayed"}, env, "")
	if disconnected.status != 0 || !strings.Contains(disconnected.stdout, "remote processes are still running") {
		t.Fatalf("disconnect = %#v", disconnected)
	}
	listed := invoke(t, binary, []string{"sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig}, env, "")
	if listed.status != 0 || !strings.Contains(listed.stdout, `"state": "disconnected"`) {
		t.Fatalf("list = %#v", listed)
	}
	reconnected := invoke(t, binary, []string{"sandbox", "reconnect", "delayed", "--kubeconfig", kubeconfig}, env, "")
	if reconnected.status != 0 {
		t.Fatalf("reconnect = %#v", reconnected)
	}
	var herdrData herdrFixture
	data, _ := os.ReadFile(herdrState)
	_ = json.Unmarshal(data, &herdrData)
	if herdrData.AddCount != 1 {
		t.Fatalf("Herdr add count = %d", herdrData.AddCount)
	}

	mismatch := invoke(t, binary, []string{"sandbox", "reconnect", "delayed", "--kubeconfig", kubeconfig}, append(env, "FAKE_HOST_KEY="+keyB), "")
	if !strings.Contains(mismatch.stderr, "host key mismatch") {
		t.Fatalf("mismatch = %#v", mismatch)
	}
	insecure := invoke(t, binary, []string{"sandbox", "create", "unsafe", "--template", "insecure", "--identity", identity, "--kubeconfig", kubeconfig}, env, "")
	if !strings.Contains(insecure.stderr, "does not meet Kubeflock pod hardening requirements") {
		t.Fatalf("insecure = %#v", insecure)
	}
	_, _, claims, methods, auths := api.snapshot()
	if _, exists := claims["unsafe"]; exists {
		t.Fatal("insecure template created a claim")
	}
	for _, method := range methods {
		if method != http.MethodGet && method != http.MethodPost {
			t.Fatalf("unexpected API method %s", method)
		}
	}
	for _, auth := range auths {
		if auth != "Bearer fixture" {
			t.Fatalf("authorization = %q; all = %#v", auth, auths)
		}
	}
}

func mustWrite(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func assertJSONField(t *testing.T, path, key, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil {
		t.Fatal("invalid JSON")
	}
	if value[key] != want {
		t.Fatalf("%s[%s] = %#v; want %q", path, key, value[key], want)
	}
}
