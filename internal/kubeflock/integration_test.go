package kubeflock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type fixtureSandbox struct {
	claim            *fixtureClaim
	mode             sandboxOperatingMode
	generation       int
	incarnation      int
	sandboxUID       string
	present          bool
	homeOwned        bool
	homeOwner        string
	homeLabeled      bool
	homeAdoptable    bool
	homeMissing      bool
	loseHomeOnDelete bool
	reads            int
}

type fixtureAPI struct {
	mu              sync.Mutex
	sandboxes       map[string]*fixtureSandbox
	failDelete      map[string]int
	failHomePatch   int
	failClaimCreate int
	mountedHome     string
	reAdoptions     int
	holdMode        bool
	creates         int
	methods         []string
	paths           []string
	auth            []string
}

func (f *fixtureAPI) ensureSandbox(name string) *fixtureSandbox {
	if f.sandboxes[name] == nil {
		f.sandboxes[name] = &fixtureSandbox{}
	}
	return f.sandboxes[name]
}

func (f *fixtureAPI) createCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates
}

func (f *fixtureAPI) apiTrace() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.methods), slices.Clone(f.auth)
}

func (f *fixtureAPI) deletePaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths)
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

func (f *fixtureAPI) failNextClaimCreate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failClaimCreate++
}

func (f *fixtureAPI) loseHomeOnDelete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSandbox(name).loseHomeOnDelete = true
}

func (f *fixtureAPI) setHomeOwned(name string, owned bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	s.homeOwned, s.homeOwner = owned, ""
}

func (f *fixtureAPI) setForeignHomeOwner(name, owner string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	s.homeOwned, s.homeOwner = false, owner
}

func (f *fixtureAPI) mountHome(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mountedHome = name
}

func (f *fixtureAPI) adoptedHomes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reAdoptions
}

func (f *fixtureAPI) claimReads(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensureSandbox(name).reads
}

func (f *fixtureAPI) hasClaim(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sandboxes[name]
	return s != nil && s.claim != nil
}

func (f *fixtureAPI) reconcileHome(s *fixtureSandbox) {
	if s.homeOwned || !s.homeLabeled {
		return
	}
	s.homeOwned = true
	f.reAdoptions++
}

type fixtureState struct {
	claim     bool
	sandbox   bool
	homeOwned bool
}

func (f *fixtureAPI) state(name string) fixtureState {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	return fixtureState{claim: s.claim != nil, sandbox: s.present, homeOwned: s.homeOwned}
}

func (f *fixtureAPI) lifecycleSnapshot(name string) (sandboxOperatingMode, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	podUID := ""
	if !f.holdMode && s.mode == modeRunning || f.holdMode && s.mode == modeSuspended {
		podUID = fmt.Sprintf("pod-%s-%d", name, s.generation)
	}
	return s.mode, podUID
}

func (f *fixtureAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(request)
	response.Header().Set("content-type", "application/json")
	f.route(response, request)
}

func (f *fixtureAPI) record(request *http.Request) {
	f.methods = append(f.methods, request.Method)
	if request.Method == http.MethodDelete {
		f.paths = append(f.paths, request.URL.Path)
	}
	f.auth = append(f.auth, request.Header.Get("Authorization"))
}

func (f *fixtureAPI) route(response http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	switch {
	case strings.Contains(path, "/sandboxtemplates/"):
		f.handleTemplate(response, path)
	case strings.HasSuffix(path, "/sandboxwarmpools"):
		f.handlePools(response)
	case strings.Contains(path, "/sandboxclaims"):
		f.handleClaims(response, request, path)
	case strings.Contains(path, "/sandboxes/"):
		f.handleSandboxes(response, request, path)
	case strings.HasSuffix(path, "/pods"):
		f.handlePods(response, request)
	case strings.Contains(path, "/persistentvolumeclaims/home-"):
		f.handleHome(response, request, path)
	default:
		writeNotFound(response)
	}
}

func writeNotFound(response http.ResponseWriter) {
	response.WriteHeader(http.StatusNotFound)
	writeFixture(response, map[string]string{"message": "not found"})
}

func (f *fixtureAPI) handleTemplate(response http.ResponseWriter, path string) {
	_, name, _ := strings.CutLast(path, "/")
	writeFixture(response, templateFixture(name, name != "insecure"))
}

func (f *fixtureAPI) handlePools(response http.ResponseWriter) {
	writeFixture(response, map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
		"kind":       "SandboxWarmPoolList",
		"items": []any{
			poolFixture("dev-small"),
			poolFixture("dev-large"),
			poolFixture("insecure"),
		},
	})
}

func (f *fixtureAPI) handleClaims(response http.ResponseWriter, request *http.Request, path string) {
	name := ""
	if strings.Contains(path, "/sandboxclaims/") {
		_, name, _ = strings.CutLast(path, "/")
	}
	switch {
	case name != "" && request.Method == http.MethodDelete:
		f.deleteClaim(response, request, name)
	case name == "" && request.Method == http.MethodPost:
		f.createClaim(response, request)
	case name == "":
		f.listClaims(response, request)
	default:
		writeNotFound(response)
	}
}

func (f *fixtureAPI) deleteClaim(response http.ResponseWriter, request *http.Request, name string) {
	s := f.ensureSandbox(name)
	if s.claim == nil || !validOrphanDelete(request, string(s.claim.Metadata.UID)) {
		response.WriteHeader(http.StatusConflict)
		return
	}
	if f.failDelete["claim"] > 0 {
		f.failDelete["claim"]--
		response.WriteHeader(http.StatusInternalServerError)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "claim delete failed", "code": 500})
		return
	}
	f.ensureSandbox(name).claim = nil
	writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200})
}

func (f *fixtureAPI) handleSandboxes(response http.ResponseWriter, request *http.Request, path string) {
	_, name, _ := strings.CutLast(path, "/")
	s := f.ensureSandbox(name)
	if request.Method == http.MethodDelete {
		f.deleteSandbox(response, request, name, s)
		return
	}
	if !s.present {
		response.WriteHeader(http.StatusNotFound)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "message": "sandbox not found", "code": 404})
		return
	}
	if request.Method == http.MethodPatch {
		f.patchMode(response, request, name, s)
		return
	}
	writeFixture(response, f.sandboxFixture(name, s.mode))
}

func (f *fixtureAPI) deleteSandbox(response http.ResponseWriter, request *http.Request, name string, s *fixtureSandbox) {
	if !validOrphanDelete(request, s.sandboxUID) {
		response.WriteHeader(http.StatusConflict)
		return
	}
	if f.failDelete["sandbox"] > 0 {
		f.failDelete["sandbox"]--
		response.WriteHeader(http.StatusInternalServerError)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "sandbox delete failed", "code": 500})
		return
	}
	s.present = false
	s.homeOwned = false
	f.reconcileHome(s)
	if s.loseHomeOnDelete {
		s.homeMissing = true
	}
	writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200})
}

func (f *fixtureAPI) patchMode(response http.ResponseWriter, request *http.Request, name string, s *fixtureSandbox) {
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
	if s.mode == modeSuspended && mode == modeRunning {
		s.generation++
	}
	s.mode = mode
	writeFixture(response, f.sandboxFixture(name, s.mode))
}

func (f *fixtureAPI) handlePods(response http.ResponseWriter, request *http.Request) {
	selector := request.URL.Query().Get("labelSelector")
	if selector == "" {
		items := []any{}
		if f.mountedHome != "" {
			items = append(items, map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": "foreign-mount", "namespace": "dev", "uid": "foreign-mount"},
				"spec":     map[string]any{"volumes": []any{map[string]any{"name": "home", "persistentVolumeClaim": map[string]string{"claimName": f.mountedHome}}}},
			})
		}
		writeFixture(response, map[string]any{"apiVersion": "v1", "kind": "PodList", "items": items})
		return
	}
	name := strings.TrimPrefix(selector, "agents.x-k8s.io/sandbox=")
	s := f.ensureSandbox(name)
	items := []any{}
	if !f.holdMode && s.mode == modeRunning || f.holdMode && s.mode == modeSuspended {
		controller := true
		items = append(items, map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name": "sandbox-" + name,
				"uid":  fmt.Sprintf("pod-%s-%d", name, s.generation),
				"ownerReferences": []any{map[string]any{
					"uid": s.sandboxUID, "controller": controller,
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
}

func (f *fixtureAPI) handleHome(response http.ResponseWriter, request *http.Request, path string) {
	_, name, _ := strings.CutLast(path, "/")
	sandbox := strings.TrimPrefix(name, "home-")
	s := f.ensureSandbox(sandbox)
	if s.homeMissing {
		response.WriteHeader(http.StatusNotFound)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "message": "persistentvolumeclaim not found", "code": 404})
		return
	}
	if request.Method == http.MethodPatch {
		f.patchHome(response, request, name, sandbox, s)
		return
	}
	writeFixture(response, homeFixture(name, sandbox, s))
}

func homeFixture(name, sandbox string, s *fixtureSandbox) map[string]any {
	controller := true
	owners := []any{}
	if s.homeOwned {
		owners = append(owners, map[string]any{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox", "name": sandbox, "uid": s.sandboxUID, "controller": controller})
	} else if s.homeOwner != "" {
		owners = append(owners, map[string]any{"apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox", "name": "foreign", "uid": s.homeOwner, "controller": controller})
	}
	labels := map[string]string{}
	if s.homeLabeled {
		labels[sandboxNameHashLabel] = "fixture"
	}
	if s.homeAdoptable {
		labels[sandboxAdoptableLabel] = "true"
	}
	return map[string]any{
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
	}
}

func (f *fixtureAPI) patchHome(response http.ResponseWriter, request *http.Request, name, sandbox string, s *fixtureSandbox) {
	data, _ := io.ReadAll(request.Body)
	if f.failHomePatch > 0 {
		f.failHomePatch--
		response.WriteHeader(http.StatusForbidden)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Forbidden", "message": "PVC patch forbidden", "code": 403})
		return
	}
	if bytes.Contains(data, []byte("ownerReferences")) {
		response.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	changed := false
	if bytes.Contains(data, []byte("sandbox-name-hash")) {
		s.homeLabeled = false
		changed = true
	}
	if bytes.Contains(data, []byte("adoptable")) {
		s.homeAdoptable = !bytes.Contains(data, []byte(`"op":"remove"`))
		changed = true
	}
	if !changed {
		response.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	writeFixture(response, homeFixture(name, sandbox, s))
}

func (f *fixtureAPI) createClaim(response http.ResponseWriter, request *http.Request) {
	if f.failClaimCreate > 0 {
		f.failClaimCreate--
		response.WriteHeader(http.StatusInternalServerError)
		writeFixture(response, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "claim create interrupted", "code": 500})
		return
	}
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
	s := f.ensureSandbox(name)
	if s.claim != nil {
		response.WriteHeader(http.StatusConflict)
		writeFixture(response, map[string]string{"message": "already exists"})
		return
	}
	f.creates++
	s.incarnation++
	s.sandboxUID = fixtureUID("sandbox", name, s.incarnation)
	claim := claimFixture(name, pool)
	claim.Metadata.UID = types.UID(fixtureUID("claim", name, s.incarnation))
	adopted := s.incarnation == 1 || s.homeAdoptable
	if adopted && name != "delayed" && name != "waiting" {
		claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
		claim.Status.Sandbox.Name = name
	} else if !adopted {
		claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "InvalidPVC", Message: "retained home is not adoptable", LastTransitionTime: metav1.Now()}}
	}
	s.claim = &claim
	s.mode = modeRunning
	s.generation = 1
	s.present = true
	s.homeOwned = adopted
	if s.incarnation == 1 {
		s.homeLabeled = true
	}
	response.WriteHeader(http.StatusCreated)
	writeFixture(response, claim)
}

func (f *fixtureAPI) listClaims(response http.ResponseWriter, request *http.Request) {
	items := []fixtureClaim{}
	field := request.URL.Query().Get("fieldSelector")
	if field == "" {
		for _, s := range f.sandboxes {
			if s.claim != nil && s.claim.Metadata.Labels[managedByLabel] == managedByValue {
				items = append(items, *s.claim)
			}
		}
		writeFixture(response, map[string]any{"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaimList", "items": items})
		return
	}
	name := strings.TrimPrefix(field, "metadata.name=")
	s := f.ensureSandbox(name)
	if s.claim != nil {
		s.reads++
		if name == "delayed" && s.reads >= 2 && s.homeOwned {
			s.claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
			s.claim.Status.Sandbox.Name = name
		}
		items = append(items, *s.claim)
	}
	writeFixture(response, map[string]any{"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaimList", "items": items})
}

func fixtureUID(kind, name string, incarnation int) string {
	if incarnation < 2 {
		return kind + "-" + name
	}
	return fmt.Sprintf("%s-%s-%d", kind, name, incarnation)
}

func (f *fixtureAPI) sandboxFixture(name string, mode sandboxOperatingMode) map[string]any {
	s := f.ensureSandbox(name)
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
	owners := []any{}
	if s.claim != nil {
		owners = append(owners, map[string]any{
			"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim", "name": name, "uid": s.claim.Metadata.UID, "controller": true,
		})
	}
	return map[string]any{
		"apiVersion": "agents.x-k8s.io/v1beta1",
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "dev",
			"uid":             s.sandboxUID,
			"resourceVersion": "1",
			"ownerReferences": owners,
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
		"image":           "example.test/sandbox@sha256:fixture",
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

func (h harness) run(t *testing.T, args ...string) result {
	t.Helper()
	return h.invoke(t, h.binary, h.env, "", args)
}

func (h harness) runWith(t *testing.T, extraEnv string, args ...string) result {
	t.Helper()
	return h.invoke(t, h.binary, append(slices.Clone(h.env), extraEnv), "", args)
}

func (h harness) runProcess(t *testing.T, binary, input string, args ...string) result {
	t.Helper()
	return h.invoke(t, binary, h.env, input, args)
}

func (h harness) invoke(t *testing.T, binary string, env []string, input string, args []string) result {
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

func (h harness) connectionState(sandboxUID string) string {
	return filepath.Join(h.stateDir, sandboxUID+".json")
}

func (h harness) proxyScript(sandboxUID string) string {
	return filepath.Join(filepath.Dir(h.sshConfig), sandboxUID+"-proxy")
}

func (h harness) retainedHomes(t *testing.T) []RetainedHome {
	t.Helper()
	listed := h.run(t, "sandbox", "home", "list", "--output", "json")
	assertCLI(t, "home list", listed, 0, "", "")
	var homes []RetainedHome
	if err := json.Unmarshal([]byte(listed.stdout), &homes); err != nil {
		t.Fatalf("home list = %#v", listed)
	}
	return homes
}

type harness struct {
	api        *fixtureAPI
	binary     string
	env        []string
	identity   string
	kubeconfig string
	stateDir   string
	sshConfig  string
	herdrState string
	kubectlLog string
}

func newHarness(t *testing.T) harness {
	t.Helper()
	dir := t.TempDir()
	api := &fixtureAPI{sandboxes: map[string]*fixtureSandbox{}, failDelete: map[string]int{}}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
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
	return harness{
		api:        api,
		binary:     binary,
		env:        []string{"GO_WANT_KUBEFLOCK_HELPER=1", "KUBEFLOCK_CONFIG=" + config, "KUBEFLOCK_STATE_DIR=" + stateDir, "KUBEFLOCK_KUBECTL=" + kubectl, "KUBEFLOCK_HERDR=" + herdr, "KUBEFLOCK_SSH_CONFIG=" + sshConfig, "FAKE_HERDR_STATE=" + herdrState, "FAKE_HOST_KEY=" + keyA, "FAKE_KUBECTL_LOG=" + kubectlLog},
		identity:   identity,
		kubeconfig: kubeconfig,
		stateDir:   stateDir,
		sshConfig:  sshConfig,
		herdrState: herdrState,
		kubectlLog: kubectlLog,
	}
}

func TestCLIConnectionAndSandboxLifecycle(t *testing.T) {
	const sandboxUID = "sandbox-delayed"
	h := newHarness(t)

	assertCLI(t, "restore action", h.run(t, "sandbox", "restore-action"), 0, "", "")
	var actionState herdrFixture
	data, _ := os.ReadFile(h.herdrState)
	_ = json.Unmarshal(data, &actionState)
	if !slices.Contains(actionState.PaneArgs, "restore") {
		t.Fatalf("restore action did not open its Herdr pane: %#v", actionState.PaneArgs)
	}

	failed := h.runWith(t, "FAKE_HERDR_FAIL_ADD=1", "sandbox", "create", "delayed", "--template", "dev-small", "--identity", h.identity, "--timeout", "10s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed create", failed, 2, "", "herdr exited")
	if creates, reads := h.api.createCount(), h.api.claimReads("delayed"); creates != 1 || reads != 2 {
		t.Fatalf("creates=%d reads=%d", creates, reads)
	}
	connectionFile := h.connectionState(sandboxUID)
	assertJSONField(t, connectionFile, "phase", "prepared")
	connected := h.run(t, "sandbox", "create", "delayed", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "connected", connected, 0, "ready sandbox delayed", "")
	if creates := h.api.createCount(); creates != 1 {
		t.Fatalf("duplicate created %d claims", creates)
	}
	assertJSONField(t, connectionFile, "phase", "connected")
	sshData, _ := os.ReadFile(h.sshConfig)
	if !strings.Contains(string(sshData), "Include ") || !strings.Contains(string(sshData), "Host unrelated") {
		t.Fatalf("SSH config lost content: %s", sshData)
	}
	proxied := h.runProcess(t, h.proxyScript(sandboxUID), "through-api")
	if proxied.status != 0 || proxied.stdout != "through-api" {
		t.Fatalf("proxy = %#v", proxied)
	}
	log, _ := os.ReadFile(h.kubectlLog)
	if !strings.Contains(string(log), "TCP:127.0.0.1:2200") {
		t.Fatalf("proxy log = %s", log)
	}

	disconnected := h.run(t, "sandbox", "disconnect", "delayed")
	assertCLI(t, "disconnect", disconnected, 0, "remote processes are still running", "")
	listed := h.run(t, "sandbox", "list", "--output", "json", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "list", listed, 0, `"state": "disconnected"`, "")
	reconnected := h.run(t, "sandbox", "reconnect", "delayed", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "reconnect", reconnected, 0, "", "")
	var herdrData herdrFixture
	data, _ = os.ReadFile(h.herdrState)
	_ = json.Unmarshal(data, &herdrData)
	if herdrData.AddCount != 1 {
		t.Fatalf("Herdr add count = %d", herdrData.AddCount)
	}

	_, originalPod := h.api.lifecycleSnapshot("delayed")
	failedDetach := h.runWith(t, "FAKE_HERDR_FAIL_DISABLE=1", "sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed detach", failedDetach, 2, "", "detach Herdr connection")
	mode, pod := h.api.lifecycleSnapshot("delayed")
	if mode != modeRunning || pod != originalPod {
		t.Fatalf("failed detach changed lifecycle: mode=%s pod=%s", mode, pod)
	}

	h.api.holdLifecycle(true)
	cancelledStop := h.run(t, "sandbox", "stop", "delayed", "--timeout", "10ms", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "cancelled stop", cancelledStop, 2, "", "timed out while entering Suspended mode")
	h.api.holdLifecycle(false)
	stopped := h.run(t, "sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "stop", stopped, 0, "persistent home retained", "requesting Suspended mode")
	mode, pod = h.api.lifecycleSnapshot("delayed")
	if mode != modeSuspended || pod != "" {
		t.Fatalf("stopped lifecycle: mode=%s pod=%s", mode, pod)
	}
	repeatedStop := h.run(t, "sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "repeated stop", repeatedStop, 0, "stopped sandbox", "")

	h.api.holdLifecycle(true)
	cancelledResume := h.run(t, "sandbox", "resume", "delayed", "--timeout", "10ms", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "cancelled resume", cancelledResume, 2, "", "timed out while entering Running mode")
	h.api.holdLifecycle(false)
	failedAttach := h.runWith(t, "FAKE_HERDR_FAIL_ENABLE=1", "sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed attach", failedAttach, 2, "", "attach Herdr connection")
	resumed := h.run(t, "sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "resume", resumed, 0, "connected as kubeflock-sandbox-delayed", "requesting Running mode")
	mode, resumedPod := h.api.lifecycleSnapshot("delayed")
	if mode != modeRunning || resumedPod == "" || resumedPod == originalPod {
		t.Fatalf("resumed lifecycle: mode=%s pod=%s", mode, resumedPod)
	}
	repeatedResume := h.run(t, "sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "repeated resume", repeatedResume, 0, "resumed sandbox", "")
	_, stablePod := h.api.lifecycleSnapshot("delayed")
	if stablePod != resumedPod {
		t.Fatalf("repeated resume replaced state: pod=%s", stablePod)
	}

	mismatch := h.runWith(t, "FAKE_HOST_KEY="+keyB, "sandbox", "reconnect", "delayed", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "mismatch", mismatch, -1, "", "host key mismatch")

	h.api.setHomeOwned("delayed", false)
	unknownOwner := h.run(t, "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "unknown home owner", unknownOwner, 2, "", "sandbox home home-delayed was replaced")
	h.api.setHomeOwned("delayed", true)

	h.api.failNextDelete("claim")
	failedClaimDelete := h.run(t, "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed claim delete", failedClaimDelete, 2, "", "orphan Sandbox from claim")
	if state := h.api.state("delayed"); !state.claim || !state.sandbox || !state.homeOwned {
		t.Fatal("claim delete failure changed ownership")
	}
	h.api.failNextHomePatch()
	failedHomePatch := h.run(t, "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed home patch", failedHomePatch, 2, "", "prevent controller re-adoption")
	if state := h.api.state("delayed"); state.claim || !state.sandbox || !state.homeOwned {
		t.Fatal("home patch failure changed ownership")
	}
	h.api.failNextDelete("sandbox")
	failedSandboxDelete := h.run(t, "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed sandbox delete", failedSandboxDelete, 2, "", "orphan home from Sandbox")
	if state := h.api.state("delayed"); state.claim || !state.sandbox || !state.homeOwned {
		t.Fatal("sandbox delete failure lost the retained home")
	}
	failedProfileRemove := h.runWith(t, "FAKE_HERDR_FAIL_REMOVE=1", "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed profile remove", failedProfileRemove, 2, "", "remove Herdr connection")
	if adopted := h.api.adoptedHomes(); adopted != 0 {
		t.Fatalf("the controller re-adopted the home %d times after orphaning", adopted)
	}
	deleted := h.run(t, "sandbox", "delete", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "delete and retain", deleted, 0, "retained home home-delayed (10Gi)", "")
	if state := h.api.state("delayed"); state.claim || state.sandbox || state.homeOwned {
		t.Fatalf("retention state: %#v", state)
	}
	for _, path := range h.api.deletePaths() {
		if strings.Contains(path, "/persistentvolumeclaims/") {
			t.Fatalf("PVC deletion requested at %s", path)
		}
	}
	if adopted := h.api.adoptedHomes(); adopted != 0 {
		t.Fatalf("the controller re-adopted the home %d times", adopted)
	}
	homes := h.retainedHomes(t)
	if len(homes) != 1 || homes[0].Home.UID != "home-delayed-uid" || homes[0].Origin.Name != "delayed" ||
		homes[0].Template != "dev-small" || homes[0].WarmPool != "dev-small-pool" || homes[0].State != "available" {
		t.Fatalf("retained homes = %#v", homes)
	}
	assertCLI(t, "retained homes text", h.run(t, "sandbox", "home", "list"), 0, "uid=home-delayed-uid", "")
	if _, err := os.Stat(connectionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("connection state still exists: %v", err)
	}
	data, _ = os.ReadFile(h.herdrState)
	_ = json.Unmarshal(data, &herdrData)
	if len(herdrData.Machines) != 1 || herdrData.Machines[0].Target != "unrelated" {
		t.Fatalf("managed Herdr profile was not removed: %#v", herdrData.Machines)
	}
	sshData, _ = os.ReadFile(h.sshConfig)
	if strings.Contains(string(sshData), "kubeflock-") || !strings.Contains(string(sshData), "Host unrelated") {
		t.Fatalf("managed SSH entry was not removed safely: %s", sshData)
	}

	outside := homes[0]
	outside.Home.UID = "outside-home-uid"
	outside.Origin.Context = "other"
	if err := saveJSON(retainedHomePath(h.stateDir, outside.Home.UID), outside); err != nil {
		t.Fatal(err)
	}
	outsideTarget := h.run(t, "sandbox", "create", "delayed", "--home", outside.Home.UID, "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "outside target", outsideTarget, 2, "", "belongs to target other/dev")
	if listed := h.retainedHomes(t); len(listed) != 1 || listed[0].Home.UID != "home-delayed-uid" {
		t.Fatalf("home list exposed another target: %#v", listed)
	}
	if err := os.Remove(retainedHomePath(h.stateDir, outside.Home.UID)); err != nil {
		t.Fatal(err)
	}

	freshSameName := h.run(t, "sandbox", "create", "delayed", "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "fresh original name", freshSameName, 2, "", "select it explicitly with --home home-delayed-uid")
	wrongName := h.run(t, "sandbox", "create", "replacement", "--home", "home-delayed-uid", "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "renamed restore", wrongName, 2, "", "can only be restored as sandbox delayed")
	wrongTemplate := h.run(t, "sandbox", "create", "delayed", "--home", "home-delayed-uid", "--template", "dev-large", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "template mismatch", wrongTemplate, 2, "", "requires template dev-small and warm pool dev-small-pool")

	h.api.setForeignHomeOwner("delayed", "sandbox-foreign")
	foreignOwner := h.run(t, "sandbox", "create", "delayed", "--home", "home-delayed-uid", "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "conflicting restore", foreignOwner, 2, "", "is owned by Sandbox/foreign")
	h.api.setHomeOwned("delayed", false)
	h.api.mountHome("home-delayed")
	mounted := h.run(t, "sandbox", "create", "delayed", "--home", "home-delayed-uid", "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "mounted restore", mounted, 2, "", "is mounted by Pod foreign-mount")
	h.api.mountHome("")

	h.api.failNextClaimCreate()
	interruptedRestore := h.run(t, "sandbox", "create", "delayed", "--home", "home-delayed-uid", "--template", "dev-small", "--identity", h.identity, "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "interrupted restore", interruptedRestore, 2, "", "claim create interrupted")
	if state := h.api.state("delayed"); state.claim || state.sandbox || state.homeOwned {
		t.Fatalf("interrupted restore made the home unrecoverable: %#v", state)
	}
	if remaining := h.retainedHomes(t); len(remaining) != 1 || remaining[0].Home.UID != "home-delayed-uid" {
		t.Fatalf("interrupted restore lost its retained record: %#v", remaining)
	}

	restored := h.run(t, "sandbox", "create", "delayed", "--home", "home-delayed-uid", "--template", "dev-small", "--identity", h.identity, "--timeout", "3s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "restore", restored, 0, "restored home home-delayed", "template dev-small image example.test/sandbox@sha256:fixture")
	if state := h.api.state("delayed"); !state.claim || !state.sandbox || !state.homeOwned {
		t.Fatalf("restore state: %#v", state)
	}
	if remaining := h.retainedHomes(t); len(remaining) != 0 {
		t.Fatalf("restored home remained available: %#v", remaining)
	}
	if _, err := os.Stat(h.connectionState("sandbox-delayed-2")); err != nil {
		t.Fatalf("restored sandbox did not get identity-bound SSH state: %v", err)
	}

	second := h.run(t, "sandbox", "create", "fragile", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "second sandbox", second, 0, "ready sandbox fragile", "")
	h.api.loseHomeOnDelete("fragile")
	lost := h.run(t, "sandbox", "delete", "fragile", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "vanished home", lost, 2, "", "no retained home was recorded")
	if remaining := h.retainedHomes(t); len(remaining) != 0 {
		t.Fatalf("a vanished home created a retained record: %#v", remaining)
	}

	insecure := h.run(t, "sandbox", "create", "unsafe", "--template", "insecure", "--identity", h.identity, "--kubeconfig", h.kubeconfig)
	assertCLI(t, "insecure", insecure, -1, "", "does not meet Kubeflock pod hardening requirements")
	methods, auths := h.api.apiTrace()
	if h.api.hasClaim("unsafe") {
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
