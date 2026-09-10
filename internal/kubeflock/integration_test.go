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
	mu               sync.Mutex
	claims           map[string]fixtureClaim
	modes            map[string]sandboxOperatingMode
	generations      map[string]int
	sandboxes        map[string]bool
	homeOwned        map[string]bool
	homeAdoptable    map[string]bool
	homeMissing      map[string]bool
	homeLostOnDelete map[string]bool
	failDelete       map[string]int
	failHomePatch    int
	reAdoptions      int
	holdMode         bool
	creates          int
	reads            map[string]int
	methods          []string
	paths            []string
	auth             []string
}

func (f *fixtureAPI) snapshot() (int, map[string]int, map[string]fixtureClaim, []string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, maps.Clone(f.reads), maps.Clone(f.claims), slices.Clone(f.methods), slices.Clone(f.auth)
}

func (f *fixtureAPI) holdLifecycle(hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holdMode = hold
}

func (f *fixtureAPI) failNextDelete(resource string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDelete[resource]++
}

func (f *fixtureAPI) failNextHomePatch() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failHomePatch++
}

func (f *fixtureAPI) loseHomeOnDelete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.homeLostOnDelete[name] = true
}

func (f *fixtureAPI) adoptedHomes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reAdoptions
}

func (f *fixtureAPI) reconcileHome(name string) {
	if f.homeOwned[name] || !f.homeAdoptable[name] {
		return
	}
	f.homeOwned[name] = true
	f.reAdoptions++
}

func (f *fixtureAPI) retentionSnapshot(name string) (claim, sandbox, homeOwned bool, paths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, claim = f.claims[name]
	return claim, f.sandboxes[name], f.homeOwned[name], slices.Clone(f.paths)
}

func (f *fixtureAPI) lifecycleSnapshot(name string) (sandboxOperatingMode, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	podUID := ""
	if !f.holdMode && f.modes[name] == modeRunning || f.holdMode && f.modes[name] == modeSuspended {
		podUID = fmt.Sprintf("pod-%s-%d", name, f.generations[name])
	}
	return f.modes[name], podUID, "home-" + name + "-uid:sha256:fixture-home"
}

func (f *fixtureAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, request.Method)
	if request.Method == http.MethodDelete {
		f.paths = append(f.paths, request.URL.Path)
	}
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
		f.createClaim(response, request)
		return
	}
	if strings.Contains(path, "/sandboxclaims/") && request.Method == http.MethodDelete {
		_, name, _ := strings.CutLast(path, "/")
		if !validOrphanDelete(request, "claim-"+name) {
			response.WriteHeader(http.StatusConflict)
			return
		}
		if f.failDelete["claim"] > 0 {
			f.failDelete["claim"]--
			response.WriteHeader(http.StatusInternalServerError)
			writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "claim delete failed", "code": 500})
			return
		}
		delete(f.claims, name)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200})
		return
	}
	if strings.HasSuffix(path, "/sandboxclaims") {
		f.listClaims(response, request)
		return
	}
	if strings.Contains(path, "/sandboxes/") {
		_, name, _ := strings.CutLast(path, "/")
		if request.Method == http.MethodDelete {
			if !validOrphanDelete(request, "sandbox-"+name) {
				response.WriteHeader(http.StatusConflict)
				return
			}
			if f.failDelete["sandbox"] > 0 {
				f.failDelete["sandbox"]--
				response.WriteHeader(http.StatusInternalServerError)
				writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "sandbox delete failed", "code": 500})
				return
			}
			f.sandboxes[name] = false
			f.homeOwned[name] = false
			f.reconcileHome(name)
			if f.homeLostOnDelete[name] {
				f.homeMissing[name] = true
			}
			writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200})
			return
		}
		if !f.sandboxes[name] {
			response.WriteHeader(http.StatusNotFound)
			writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "message": "sandbox not found", "code": 404})
			return
		}
		if request.Method == http.MethodPatch {
			var operations []struct {
				Path  string               `json:"path"`
				Value sandboxOperatingMode `json:"value"`
			}
			if json.NewDecoder(request.Body).Decode(&operations) != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			mode := sandboxOperatingMode("")
			for _, operation := range operations {
				if operation.Path == "/spec/operatingMode" {
					mode = operation.Value
				}
			}
			if mode != modeRunning && mode != modeSuspended {
				response.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			if f.modes[name] == modeSuspended && mode == modeRunning {
				f.generations[name]++
			}
			f.modes[name] = mode
		}
		writeFixture(response, f.sandboxFixture(name))
		return
	}
	if strings.HasSuffix(path, "/pods") {
		name := strings.TrimPrefix(request.URL.Query().Get("labelSelector"), "agents.x-k8s.io/sandbox=")
		items := []any{}
		running := !f.holdMode && f.modes[name] == modeRunning || f.holdMode && f.modes[name] == modeSuspended
		if running {
			controller := true
			items = append(items, map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name": "sandbox-" + name,
					"uid":  fmt.Sprintf("pod-%s-%d", name, f.generations[name]),
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
			})
		}
		writeFixture(response, map[string]any{"apiVersion": "v1", "kind": "PodList", "items": items})
		return
	}
	if strings.Contains(path, "/persistentvolumeclaims/home-") {
		_, name, _ := strings.CutLast(path, "/")
		sandbox := strings.TrimPrefix(name, "home-")
		if f.homeMissing[sandbox] {
			response.WriteHeader(http.StatusNotFound)
			writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "message": "persistentvolumeclaim not found", "code": 404})
			return
		}
		if request.Method == http.MethodPatch {
			data, _ := io.ReadAll(request.Body)
			if f.failHomePatch > 0 {
				f.failHomePatch--
				response.WriteHeader(http.StatusForbidden)
				writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Forbidden", "message": "PVC patch forbidden", "code": 403})
				return
			}
			if !bytes.Contains(data, []byte("sandbox-name-hash")) || bytes.Contains(data, []byte("ownerReferences")) {
				response.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			f.homeAdoptable[sandbox] = false
		}
		controller := true
		owners := []any{}
		if f.homeOwned[sandbox] {
			owners = append(owners, map[string]any{"uid": "sandbox-" + sandbox, "controller": controller})
		}
		labels := map[string]string{}
		if f.homeAdoptable[sandbox] {
			labels[sandboxNameHashLabel] = "fixture"
		}
		writeFixture(response, map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":            name,
				"namespace":       "dev",
				"uid":             name + "-uid",
				"resourceVersion": "1",
				"labels":          labels,
				"ownerReferences": owners,
			},
			"spec":   map[string]any{"storageClassName": "longhorn"},
			"status": map[string]any{"capacity": map[string]string{"storage": "10Gi"}},
		})
		return
	}
	response.WriteHeader(http.StatusNotFound)
	writeFixture(response, map[string]string{"message": "not found"})
}

func (f *fixtureAPI) createClaim(response http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if json.NewDecoder(request.Body).Decode(&body) != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	metadata, metadataOK := body["metadata"].(map[string]any)
	spec, specOK := body["spec"].(map[string]any)
	if !metadataOK || !specOK {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	ref, refOK := spec["warmPoolRef"].(map[string]any)
	name, nameOK := metadata["name"].(string)
	if !refOK || !nameOK {
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
	f.modes[name] = modeRunning
	f.generations[name] = 1
	f.sandboxes[name] = true
	f.homeOwned[name] = true
	f.homeAdoptable[name] = true
	response.WriteHeader(http.StatusCreated)
	writeFixture(response, claim)
}

func (f *fixtureAPI) listClaims(response http.ResponseWriter, request *http.Request) {
	items := []fixtureClaim{}
	field := request.URL.Query().Get("fieldSelector")
	if field == "" {
		for _, claim := range f.claims {
			if claim.Metadata.Labels[managedByLabel] == managedByValue {
				items = append(items, claim)
			}
		}
		writeFixture(response, map[string]any{"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaimList", "items": items})
		return
	}
	name := strings.TrimPrefix(field, "metadata.name=")
	claim, ok := f.claims[name]
	if ok {
		f.reads[name]++
		if name == "delayed" && f.reads[name] >= 2 {
			claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
			claim.Status.Sandbox.Name = name
			f.claims[name] = claim
		}
		items = append(items, claim)
	}
	writeFixture(response, map[string]any{"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaimList", "items": items})
}

func (f *fixtureAPI) sandboxFixture(name string) map[string]any {
	mode := f.modes[name]
	observed := mode
	if f.holdMode {
		if mode == modeRunning {
			observed = modeSuspended
		} else {
			observed = modeRunning
		}
	}
	condition := map[string]string{"type": "Ready", "status": "True", "reason": "Ready"}
	if observed == modeSuspended {
		condition = map[string]string{"type": "Suspended", "status": "True", "reason": "Suspended"}
	}
	return map[string]any{
		"apiVersion": "agents.x-k8s.io/v1beta1",
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "dev",
			"uid":             "sandbox-" + name,
			"resourceVersion": "1",
		},
		"spec": map[string]any{"operatingMode": mode},
		"status": map[string]any{
			"selector":   "agents.x-k8s.io/sandbox=" + name,
			"conditions": []any{condition},
		},
	}
}

func validOrphanDelete(request *http.Request, uid string) bool {
	var options metav1.DeleteOptions
	return json.NewDecoder(request.Body).Decode(&options) == nil &&
		options.PropagationPolicy != nil && *options.PropagationPolicy == metav1.DeletePropagationOrphan &&
		options.Preconditions != nil && options.Preconditions.UID != nil && string(*options.Preconditions.UID) == uid
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
	if len(args) == 3 && args[0] == "machine" && args[1] == "remove" {
		if os.Getenv("FAKE_HERDR_FAIL_REMOVE") == "1" {
			os.Exit(1)
		}
		state.Machines = slices.DeleteFunc(state.Machines, func(machine herdrMachine) bool { return machine.ID == args[2] })
		save()
		return
	}
	if len(args) == 3 && args[0] == "machine" && (args[1] == "enable" || args[1] == "disable") {
		if os.Getenv("FAKE_HERDR_FAIL_"+strings.ToUpper(args[1])) == "1" {
			os.Exit(1)
		}
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
	api := &fixtureAPI{
		claims: map[string]fixtureClaim{}, modes: map[string]sandboxOperatingMode{}, generations: map[string]int{},
		sandboxes: map[string]bool{}, homeOwned: map[string]bool{}, homeAdoptable: map[string]bool{},
		homeMissing: map[string]bool{}, homeLostOnDelete: map[string]bool{}, failDelete: map[string]int{}, reads: map[string]int{},
	}
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
	assertCLI(t, "failed create", failed, 2, "", "herdr exited")
	creates, reads, _, _, _ := api.snapshot()
	if creates != 1 || reads["delayed"] != 2 {
		t.Fatalf("creates=%d reads=%d", creates, reads["delayed"])
	}
	connectionFile := filepath.Join(stateDir, "sandbox-delayed.json")
	assertJSONField(t, connectionFile, "phase", "prepared")
	connected := invoke(t, binary, []string{"sandbox", "create", "delayed", "--template", "dev-small", "--identity", identity, "--timeout", "2s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "connected", connected, 0, "ready sandbox delayed", "")
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
	assertCLI(t, "disconnect", disconnected, 0, "remote processes are still running", "")
	listed := invoke(t, binary, []string{"sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "list", listed, 0, `"state": "disconnected"`, "")
	reconnected := invoke(t, binary, []string{"sandbox", "reconnect", "delayed", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "reconnect", reconnected, 0, "", "")
	var herdrData herdrFixture
	data, _ := os.ReadFile(herdrState)
	_ = json.Unmarshal(data, &herdrData)
	if herdrData.AddCount != 1 {
		t.Fatalf("Herdr add count = %d", herdrData.AddCount)
	}

	_, originalPod, originalHome := api.lifecycleSnapshot("delayed")
	failedDetach := invoke(t, binary, []string{"sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, append(env, "FAKE_HERDR_FAIL_DISABLE=1"), "")
	assertCLI(t, "failed detach", failedDetach, 2, "", "detach Herdr connection")
	mode, pod, home := api.lifecycleSnapshot("delayed")
	if mode != modeRunning || pod != originalPod || home != originalHome {
		t.Fatalf("failed detach changed lifecycle: mode=%s pod=%s home=%s", mode, pod, home)
	}

	api.holdLifecycle(true)
	cancelledStop := invoke(t, binary, []string{"sandbox", "stop", "delayed", "--timeout", "10ms", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "cancelled stop", cancelledStop, 2, "", "timed out while entering Suspended mode")
	api.holdLifecycle(false)
	stopped := invoke(t, binary, []string{"sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "stop", stopped, 0, "persistent home retained", "requesting Suspended mode")
	mode, pod, home = api.lifecycleSnapshot("delayed")
	if mode != modeSuspended || pod != "" || home != originalHome {
		t.Fatalf("stopped lifecycle: mode=%s pod=%s home=%s", mode, pod, home)
	}
	repeatedStop := invoke(t, binary, []string{"sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "repeated stop", repeatedStop, 0, "stopped sandbox", "")

	api.holdLifecycle(true)
	cancelledResume := invoke(t, binary, []string{"sandbox", "resume", "delayed", "--timeout", "10ms", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "cancelled resume", cancelledResume, 2, "", "timed out while entering Running mode")
	api.holdLifecycle(false)
	failedAttach := invoke(t, binary, []string{"sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, append(env, "FAKE_HERDR_FAIL_ENABLE=1"), "")
	assertCLI(t, "failed attach", failedAttach, 2, "", "attach Herdr connection")
	resumed := invoke(t, binary, []string{"sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "resume", resumed, 0, "connected as kubeflock-sandbox-delayed", "requesting Running mode")
	mode, resumedPod, home := api.lifecycleSnapshot("delayed")
	if mode != modeRunning || resumedPod == "" || resumedPod == originalPod || home != originalHome {
		t.Fatalf("resumed lifecycle: mode=%s pod=%s home=%s", mode, resumedPod, home)
	}
	repeatedResume := invoke(t, binary, []string{"sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "repeated resume", repeatedResume, 0, "resumed sandbox", "")
	_, stablePod, stableHome := api.lifecycleSnapshot("delayed")
	if stablePod != resumedPod || stableHome != originalHome {
		t.Fatalf("repeated resume replaced state: pod=%s home=%s", stablePod, stableHome)
	}

	mismatch := invoke(t, binary, []string{"sandbox", "reconnect", "delayed", "--kubeconfig", kubeconfig}, append(env, "FAKE_HOST_KEY="+keyB), "")
	assertCLI(t, "mismatch", mismatch, -1, "", "host key mismatch")

	api.mu.Lock()
	api.homeOwned["delayed"] = false
	api.mu.Unlock()
	unknownOwner := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "unknown home owner", unknownOwner, 2, "", "sandbox home home-delayed was replaced")
	api.mu.Lock()
	api.homeOwned["delayed"] = true
	api.mu.Unlock()

	api.failNextDelete("claim")
	failedClaimDelete := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "failed claim delete", failedClaimDelete, 2, "", "orphan Sandbox from claim")
	claim, sandbox, owned, _ := api.retentionSnapshot("delayed")
	if !claim || !sandbox || !owned {
		t.Fatal("claim delete failure changed ownership")
	}
	api.failNextHomePatch()
	failedHomePatch := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "failed home patch", failedHomePatch, 2, "", "prevent controller re-adoption")
	claim, sandbox, owned, _ = api.retentionSnapshot("delayed")
	if claim || !sandbox || !owned {
		t.Fatal("home patch failure changed ownership")
	}
	api.failNextDelete("sandbox")
	failedSandboxDelete := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "failed sandbox delete", failedSandboxDelete, 2, "", "orphan home from Sandbox")
	claim, sandbox, owned, _ = api.retentionSnapshot("delayed")
	if claim || !sandbox || !owned {
		t.Fatal("sandbox delete failure lost the retained home")
	}
	failedProfileRemove := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, append(env, "FAKE_HERDR_FAIL_REMOVE=1"), "")
	assertCLI(t, "failed profile remove", failedProfileRemove, 2, "", "remove Herdr connection")
	if adopted := api.adoptedHomes(); adopted != 0 {
		t.Fatalf("the controller re-adopted the home %d times after orphaning", adopted)
	}
	deleted := invoke(t, binary, []string{"sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "delete and retain", deleted, 0, "retained home home-delayed-uid", "stopping compute")
	claim, sandbox, owned, paths := api.retentionSnapshot("delayed")
	if claim || sandbox || owned {
		t.Fatalf("retention state: claim=%v sandbox=%v owned=%v", claim, sandbox, owned)
	}
	for _, path := range paths {
		if strings.Contains(path, "/persistentvolumeclaims/") {
			t.Fatalf("PVC deletion requested at %s", path)
		}
	}
	if adopted := api.adoptedHomes(); adopted != 0 {
		t.Fatalf("the controller re-adopted the home %d times", adopted)
	}
	homes := retainedHomes(t, binary, env)
	if len(homes) != 1 || homes[0].Home.UID != "home-delayed-uid" || homes[0].Origin.Name != "delayed" ||
		homes[0].Template != "dev-small" || homes[0].WarmPool != "dev-small-pool" || homes[0].State != "available" {
		t.Fatalf("retained homes = %#v", homes)
	}
	assertCLI(t, "retained homes text", invoke(t, binary, []string{"sandbox", "home", "list"}, env, ""), 0, "template=dev-small", "")
	if _, err := os.Stat(connectionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("connection state still exists: %v", err)
	}
	data, _ = os.ReadFile(herdrState)
	_ = json.Unmarshal(data, &herdrData)
	if len(herdrData.Machines) != 1 || herdrData.Machines[0].Target != "unrelated" {
		t.Fatalf("managed Herdr profile was not removed: %#v", herdrData.Machines)
	}
	sshData, _ = os.ReadFile(sshConfig)
	if strings.Contains(string(sshData), "kubeflock-") || !strings.Contains(string(sshData), "Host unrelated") {
		t.Fatalf("managed SSH entry was not removed safely: %s", sshData)
	}

	second := invoke(t, binary, []string{"sandbox", "create", "fragile", "--template", "dev-small", "--identity", identity, "--timeout", "2s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "second sandbox", second, 0, "ready sandbox fragile", "")
	api.loseHomeOnDelete("fragile")
	lost := invoke(t, binary, []string{"sandbox", "delete", "fragile", "--timeout", "1s", "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "vanished home", lost, 2, "", "no retained home was recorded")
	if remaining := retainedHomes(t, binary, env); len(remaining) != 1 || remaining[0].Origin.Name != "delayed" {
		t.Fatalf("a vanished home changed the retained list: %#v", remaining)
	}

	insecure := invoke(t, binary, []string{"sandbox", "create", "unsafe", "--template", "insecure", "--identity", identity, "--kubeconfig", kubeconfig}, env, "")
	assertCLI(t, "insecure", insecure, -1, "", "does not meet Kubeflock pod hardening requirements")
	_, _, claims, methods, auths := api.snapshot()
	if _, exists := claims["unsafe"]; exists {
		t.Fatal("insecure template created a claim")
	}
	assertAPITrace(t, methods, auths)
}

func TestConditionObservedRequiresCurrentGeneration(t *testing.T) {
	condition := &metav1.Condition{Status: metav1.ConditionTrue, ObservedGeneration: 2}
	if conditionObserved(condition, 3, metav1.ConditionTrue) {
		t.Fatal("accepted a stale Ready condition")
	}
	if !conditionObserved(condition, 2, metav1.ConditionTrue) {
		t.Fatal("rejected the current Ready condition")
	}
}

func assertAPITrace(t *testing.T, methods, auths []string) {
	t.Helper()
	for _, method := range methods {
		if method != http.MethodGet && method != http.MethodPost && method != http.MethodPatch && method != http.MethodDelete {
			t.Fatalf("unexpected API method %s", method)
		}
	}
	for _, auth := range auths {
		if auth != "Bearer fixture" {
			t.Fatalf("authorization = %q; all = %#v", auth, auths)
		}
	}
}

func assertCLI(t *testing.T, label string, got result, status int, stdout, stderr string) {
	t.Helper()
	if status >= 0 && got.status != status {
		t.Fatalf("%s = %#v", label, got)
	}
	if stdout != "" && !strings.Contains(got.stdout, stdout) {
		t.Fatalf("%s = %#v", label, got)
	}
	if stderr != "" && !strings.Contains(got.stderr, stderr) {
		t.Fatalf("%s = %#v", label, got)
	}
}

func retainedHomes(t *testing.T, binary string, env []string) []RetainedHome {
	t.Helper()
	listed := invoke(t, binary, []string{"sandbox", "home", "list", "--output", "json"}, env, "")
	assertCLI(t, "home list", listed, 0, "", "")
	var homes []RetainedHome
	if err := json.Unmarshal([]byte(listed.stdout), &homes); err != nil {
		t.Fatalf("home list = %#v", listed)
	}
	return homes
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
