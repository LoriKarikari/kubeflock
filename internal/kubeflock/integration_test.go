package kubeflock

import (
	"bytes"
	"cmp"
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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/runtime/serializer/recognizer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	sandboxapi "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsapi "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
)

var deleteOptionsCodec = func() runtime.Decoder {
	scheme := runtime.NewScheme()
	utilruntime.Must(metav1.AddMetaToScheme(scheme))
	return recognizer.NewDecoder(protobuf.NewSerializer(scheme, scheme))
}()

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type fixtureSandbox struct {
	claim            *extensionsapi.SandboxClaim
	mode             sandboxOperatingMode
	generation       int
	incarnation      int
	sandboxUID       string
	present          bool
	homeOwned        bool
	homeOwner        string
	homeLabeled      bool
	homeAdoptable    bool
	homeStorageClass string
	homeCapacity     string
	homeAccessModes  []corev1.PersistentVolumeAccessMode
	homeVolumeMode   corev1.PersistentVolumeMode
	homeUID          string
	homeMissing      bool
	volumePolicy     corev1.PersistentVolumeReclaimPolicy
	volumeMissing    bool
	holdVolume       bool
	holdDelete       bool
	terminating      bool
	loseHomeOnDelete bool
	reads            int
}

type fixtureAPI struct {
	t               *testing.T
	mu              sync.Mutex
	sandboxes       map[string]*fixtureSandbox
	failDelete      map[string]int
	failHomePatch   int
	failClaimCreate int
	templateClaim   string
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

func (f *fixtureAPI) apiTrace() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.methods), slices.Clone(f.auth)
}

func (f *fixtureAPI) setHomeOwned(name string, owned bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	s.homeOwned, s.homeOwner = owned, ""
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
	claim         bool
	sandbox       bool
	homeOwned     bool
	homeMissing   bool
	volumeMissing bool
}

func (f *fixtureAPI) state(name string) fixtureState {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.ensureSandbox(name)
	return fixtureState{claim: s.claim != nil, sandbox: s.present, homeOwned: s.homeOwned, homeMissing: s.homeMissing, volumeMissing: s.volumeMissing}
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
	case strings.Contains(path, "/persistentvolumes/pv-home-"):
		f.handleVolume(response, request, path)
	default:
		f.writeNotFound(response)
	}
}

func (f *fixtureAPI) writeNotFound(response http.ResponseWriter) {
	response.WriteHeader(http.StatusNotFound)
	f.writeFixture(response, map[string]string{"message": "not found"})
}

func (f *fixtureAPI) handleTemplate(response http.ResponseWriter, path string) {
	_, name, _ := strings.CutLast(path, "/")
	f.writeFixture(response, templateFixture(name, name != "insecure", cmp.Or(f.templateClaim, "home")))
}

func (f *fixtureAPI) handlePools(response http.ResponseWriter) {
	f.writeFixture(response, extensionsapi.SandboxWarmPoolList{
		APIVersion: "extensions.agents.x-k8s.io/v1beta1",
		Kind:       "SandboxWarmPoolList",
		Items: []extensionsapi.SandboxWarmPool{
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
	case name != "" && request.Method == http.MethodGet:
		f.getClaim(response, name)
	case name != "" && request.Method == http.MethodDelete:
		f.deleteClaim(response, request, name)
	case name == "" && request.Method == http.MethodPost:
		f.createClaim(response, request)
	case name == "":
		f.listClaims(response)
	default:
		f.writeNotFound(response)
	}
}

func (f *fixtureAPI) deleteClaim(response http.ResponseWriter, request *http.Request, name string) {
	s := f.ensureSandbox(name)
	if s.claim == nil || !validOrphanDelete(request, string(s.claim.UID)) {
		response.WriteHeader(http.StatusConflict)
		return
	}
	if f.failDelete["claim"] > 0 {
		f.failDelete["claim"]--
		response.WriteHeader(http.StatusInternalServerError)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Message: "claim delete failed", Code: 500})
		return
	}
	s.claim = nil
	f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Success", Code: 200})
}

func (f *fixtureAPI) handleSandboxes(response http.ResponseWriter, request *http.Request, path string) {
	_, name, _ := strings.CutLast(path, "/")
	s := f.ensureSandbox(name)
	if request.Method == http.MethodDelete {
		f.deleteSandbox(response, request, s)
		return
	}
	if !s.present {
		response.WriteHeader(http.StatusNotFound)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonNotFound, Message: "sandbox not found", Code: 404})
		return
	}
	if request.Method == http.MethodPatch {
		f.patchMode(response, request, name, s)
		return
	}
	f.writeFixture(response, f.sandboxFixture(name, s.mode))
}

func (f *fixtureAPI) deleteSandbox(response http.ResponseWriter, request *http.Request, s *fixtureSandbox) {
	if !validOrphanDelete(request, s.sandboxUID) {
		response.WriteHeader(http.StatusConflict)
		return
	}
	if f.failDelete["sandbox"] > 0 {
		f.failDelete["sandbox"]--
		response.WriteHeader(http.StatusInternalServerError)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Message: "sandbox delete failed", Code: 500})
		return
	}
	s.present = false
	s.homeOwned = false
	f.reconcileHome(s)
	if s.loseHomeOnDelete {
		s.homeMissing = true
	}
	f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Success", Code: 200})
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
	if s.claim != nil {
		s.claim.Status.Conditions = []metav1.Condition{claimCondition(mode)}
	}
	f.writeFixture(response, f.sandboxFixture(name, s.mode))
}

func claimCondition(mode sandboxOperatingMode) metav1.Condition {
	if mode == modeSuspended {
		return metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "SandboxSuspended", Message: "Sandbox is suspended"}
	}
	return metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready"}
}

func (f *fixtureAPI) handlePods(response http.ResponseWriter, request *http.Request) {
	pods := corev1.PodList{APIVersion: "v1", Kind: "PodList", Items: []corev1.Pod{}}
	selector := request.URL.Query().Get("labelSelector")
	if selector == "" {
		if f.mountedHome != "" {
			pods.Items = append(pods.Items, corev1.Pod{
				APIVersion: "v1", Kind: "Pod", Name: "foreign-mount", Namespace: "dev", UID: "foreign-mount",
				Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
					Name: "home", PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: f.mountedHome},
				}}},
			})
		}
		f.writeFixture(response, pods)
		return
	}
	name := strings.TrimPrefix(selector, "agents.x-k8s.io/sandbox=")
	s := f.ensureSandbox(name)
	if !f.holdMode && s.mode == modeRunning || f.holdMode && s.mode == modeSuspended {
		pods.Items = append(pods.Items, corev1.Pod{
			APIVersion: "v1", Kind: "Pod", Name: "sandbox-" + name,
			UID:             types.UID(fmt.Sprintf("pod-%s-%d", name, s.generation)),
			OwnerReferences: []metav1.OwnerReference{{UID: types.UID(s.sandboxUID), Controller: new(true)}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "sandbox", Ports: []corev1.ContainerPort{{Name: "ssh", ContainerPort: 2200}},
			}}},
		})
	}
	f.writeFixture(response, pods)
}

func (f *fixtureAPI) handleHome(response http.ResponseWriter, request *http.Request, path string) {
	_, name, _ := strings.CutLast(path, "/")
	sandbox := strings.TrimPrefix(name, "home-")
	s := f.ensureSandbox(sandbox)
	if s.homeMissing {
		response.WriteHeader(http.StatusNotFound)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonNotFound, Message: "persistentvolumeclaim not found", Code: 404})
		return
	}
	if request.Method == http.MethodDelete {
		uid := types.UID(homeUID(name, s))
		options, ok := deleteOptions(request.Body)
		if !ok || options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != uid {
			response.WriteHeader(http.StatusConflict)
			f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonConflict, Message: fmt.Sprintf("PVC UID precondition did not match %s", uid), Code: 409})
			return
		}
		if f.failDelete["pvc"] > 0 {
			f.failDelete["pvc"]--
			response.WriteHeader(http.StatusForbidden)
			f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonForbidden, Message: "PVC delete forbidden", Code: 403})
			return
		}
		s.terminating, s.homeMissing = s.holdDelete, !s.holdDelete
		if s.homeMissing && s.volumePolicy != corev1.PersistentVolumeReclaimRetain && !s.holdVolume {
			s.volumeMissing = true
		}
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Success", Code: 200})
		return
	}
	if request.Method == http.MethodPatch {
		f.patchHome(response, request, name, sandbox, s)
		return
	}
	f.writeFixture(response, homeFixture(name, sandbox, s))
}

func (f *fixtureAPI) handleVolume(response http.ResponseWriter, request *http.Request, path string) {
	_, name, _ := strings.CutLast(path, "/")
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonMethodNotAllowed, Message: "persistent volumes do not accept " + request.Method, Code: 405})
		return
	}
	sandbox := strings.TrimPrefix(name, "pv-home-")
	s := f.ensureSandbox(sandbox)
	if s.volumeMissing {
		f.writeNotFound(response)
		return
	}
	policy := s.volumePolicy
	if policy == "" {
		policy = corev1.PersistentVolumeReclaimDelete
	}
	f.writeFixture(response, corev1.PersistentVolume{
		APIVersion: "v1", Kind: "PersistentVolume", Name: name, UID: types.UID(name + "-uid"),
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: policy,
			ClaimRef:                      &corev1.ObjectReference{Namespace: "dev", Name: "home-" + sandbox, UID: types.UID(homeUID("home-"+sandbox, s))},
		},
	})
}

func homeUID(name string, s *fixtureSandbox) string {
	if s.homeUID != "" {
		return s.homeUID
	}
	return name + "-uid"
}

func deleteOptions(body io.Reader) (metav1.DeleteOptions, bool) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return metav1.DeleteOptions{}, false
	}
	var options metav1.DeleteOptions
	if json.Unmarshal(raw, &options) == nil {
		return options, true
	}
	if _, _, err := deleteOptionsCodec.Decode(raw, nil, &options); err != nil {
		return metav1.DeleteOptions{}, false
	}
	return options, true
}

func homeFixture(name, sandbox string, s *fixtureSandbox) corev1.PersistentVolumeClaim {
	var owners []metav1.OwnerReference
	if s.homeOwned {
		owners = append(owners, metav1.OwnerReference{APIVersion: "agents.x-k8s.io/v1beta1", Kind: "Sandbox", Name: sandbox, UID: types.UID(s.sandboxUID), Controller: new(true)})
	} else if s.homeOwner != "" {
		owners = append(owners, metav1.OwnerReference{APIVersion: "agents.x-k8s.io/v1beta1", Kind: "Sandbox", Name: "foreign", UID: types.UID(s.homeOwner), Controller: new(true)})
	}
	labels := map[string]string{}
	if s.homeLabeled {
		labels[sandboxNameHashLabel] = "fixture"
	}
	if s.homeAdoptable {
		labels[sandboxapi.SandboxAdoptableLabel] = "true"
	}
	storageClass, capacity := s.homeStorageClass, s.homeCapacity
	if storageClass == "" {
		storageClass = "longhorn"
	}
	if capacity == "" {
		capacity = "10Gi"
	}
	accessModes := s.homeAccessModes
	if accessModes == nil {
		accessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	}
	pvc := corev1.PersistentVolumeClaim{
		APIVersion: "v1", Kind: "PersistentVolumeClaim",
		Name: name, Namespace: "dev", UID: types.UID(homeUID(name, s)), ResourceVersion: "1",
		Labels: labels, OwnerReferences: owners,
		Spec:   corev1.PersistentVolumeClaimSpec{StorageClassName: &storageClass, AccessModes: accessModes, VolumeName: "pv-" + name},
		Status: corev1.PersistentVolumeClaimStatus{Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(capacity)}},
	}
	if s.homeVolumeMode != "" {
		pvc.Spec.VolumeMode = &s.homeVolumeMode
	}
	if s.terminating {
		pvc.DeletionTimestamp = new(metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
	}
	return pvc
}

func (f *fixtureAPI) patchHome(response http.ResponseWriter, request *http.Request, name, sandbox string, s *fixtureSandbox) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.failHomePatch > 0 {
		f.failHomePatch--
		response.WriteHeader(http.StatusForbidden)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonForbidden, Message: "PVC patch forbidden", Code: 403})
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
	f.writeFixture(response, homeFixture(name, sandbox, s))
}

func (f *fixtureAPI) createClaim(response http.ResponseWriter, request *http.Request) {
	if f.failClaimCreate > 0 {
		f.failClaimCreate--
		response.WriteHeader(http.StatusInternalServerError)
		f.writeFixture(response, metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Message: "claim create interrupted", Code: 500})
		return
	}
	var body extensionsapi.SandboxClaim
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.Name == "" || body.Spec.WarmPoolRef.Name == "" {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	name := body.Name
	s := f.ensureSandbox(name)
	if s.claim != nil {
		response.WriteHeader(http.StatusConflict)
		f.writeFixture(response, map[string]string{"message": "already exists"})
		return
	}
	f.creates++
	s.incarnation++
	sandboxName := name
	if name == "warm" {
		sandboxName = "dev-small-standby"
		f.sandboxes[sandboxName] = s
	}
	s.sandboxUID = fixtureUID("sandbox", sandboxName, s.incarnation)
	claim := claimFixture(name, body.Spec.WarmPoolRef.Name)
	claim.Spec.VolumeClaimTemplates = body.Spec.VolumeClaimTemplates
	claim.UID = types.UID(fixtureUID("claim", name, s.incarnation))
	adopted := s.incarnation == 1 || s.homeAdoptable
	if adopted && name != "delayed" && name != "waiting" {
		claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
		claim.Status.SandboxStatus.Name = sandboxName
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
	f.writeFixture(response, claim)
}

func (f *fixtureAPI) getClaim(response http.ResponseWriter, name string) {
	s := f.ensureSandbox(name)
	if s.claim == nil {
		f.writeNotFound(response)
		return
	}
	s.reads++
	if name == "delayed" && s.reads >= 2 && s.homeOwned && s.mode != modeSuspended {
		s.claim.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.Now()}}
		s.claim.Status.SandboxStatus.Name = name
	}
	f.writeFixture(response, s.claim)
}

func (f *fixtureAPI) listClaims(response http.ResponseWriter) {
	items := []extensionsapi.SandboxClaim{}
	for _, s := range f.sandboxes {
		if s.claim != nil && s.claim.Labels[managedByLabel] == managedByValue {
			items = append(items, *s.claim)
		}
	}
	f.writeFixture(response, extensionsapi.SandboxClaimList{APIVersion: "extensions.agents.x-k8s.io/v1beta1", Kind: "SandboxClaimList", Items: items})
}

func fixtureUID(kind, name string, incarnation int) string {
	if incarnation < 2 {
		return kind + "-" + name
	}
	return fmt.Sprintf("%s-%s-%d", kind, name, incarnation)
}

func (f *fixtureAPI) sandboxFixture(name string, mode sandboxOperatingMode) sandboxapi.Sandbox {
	s := f.ensureSandbox(name)
	observed := mode
	if f.holdMode {
		if mode == modeRunning {
			observed = modeSuspended
		} else {
			observed = modeRunning
		}
	}
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready"}
	if observed == modeSuspended {
		condition.Type, condition.Reason = "Suspended", "Suspended"
	}
	sandbox := sandboxapi.Sandbox{
		APIVersion: "agents.x-k8s.io/v1beta1", Kind: "Sandbox",
		Name: name, Namespace: "dev", UID: types.UID(s.sandboxUID), ResourceVersion: "1",
		Spec: sandboxapi.SandboxSpec{OperatingMode: mode},
		Status: sandboxapi.SandboxStatus{
			LabelSelector: "agents.x-k8s.io/sandbox=" + name,
			Conditions:    []metav1.Condition{condition},
		},
	}
	if s.claim != nil {
		sandbox.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "extensions.agents.x-k8s.io/v1beta1", Kind: "SandboxClaim", Name: name, UID: s.claim.UID, Controller: new(true),
		}}
	}
	return sandbox
}

func validOrphanDelete(request *http.Request, uid string) bool {
	var options metav1.DeleteOptions
	return json.NewDecoder(request.Body).Decode(&options) == nil &&
		options.PropagationPolicy != nil && *options.PropagationPolicy == metav1.DeletePropagationOrphan &&
		options.Preconditions != nil && options.Preconditions.UID != nil && string(*options.Preconditions.UID) == uid
}

func (f *fixtureAPI) writeFixture(writer io.Writer, value any) {
	f.t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		f.t.Errorf("write API fixture: %v", err)
	}
}

func poolFixture(template string) extensionsapi.SandboxWarmPool {
	return extensionsapi.SandboxWarmPool{
		APIVersion: "extensions.agents.x-k8s.io/v1beta1",
		Kind:       "SandboxWarmPool",
		Name:       template + "-pool",
		Namespace:  "dev",
		UID:        types.UID(template + "-pool-uid"),
		Spec: extensionsapi.SandboxWarmPoolSpec{
			Replicas:    new(int32(1)),
			TemplateRef: extensionsapi.SandboxTemplateRef{Name: template},
		},
	}
}

func claimFixture(name, pool string) extensionsapi.SandboxClaim {
	return extensionsapi.SandboxClaim{
		APIVersion: "extensions.agents.x-k8s.io/v1beta1",
		Kind:       "SandboxClaim",
		Name:       name,
		Namespace:  "dev",
		UID:        types.UID("claim-" + name),
		Labels:     map[string]string{managedByLabel: managedByValue},
		Spec:       extensionsapi.SandboxClaimSpec{WarmPoolRef: extensionsapi.SandboxWarmPoolRef{Name: pool}},
	}
}

func templateFixture(name string, secure bool, homeClaim string) extensionsapi.SandboxTemplate {
	template := gateTemplate()
	template.APIVersion, template.Kind = "extensions.agents.x-k8s.io/v1beta1", "SandboxTemplate"
	template.Name, template.Namespace, template.UID = name, "dev", types.UID(name+"-uid")
	pod := &template.Spec.PodTemplate.Spec
	if !secure {
		pod.RuntimeClassName = new("runc")
	}
	container := &pod.Containers[0]
	container.Name = ""
	container.Image = "example.test/sandbox@sha256:fixture"
	container.Ports[0].ContainerPort = 2200
	container.Resources.Requests[corev1.ResourceMemory] = resource.MustParse("1Gi")
	container.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("4Gi")
	pod.Volumes[0].PersistentVolumeClaim.ClaimName = homeClaim
	template.Spec.VolumeClaimTemplates[0].Name = homeClaim
	template.Spec.VolumeClaimTemplates[0].Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	return template
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
		info := os.Getenv("KUBERNETES_EXEC_INFO")
		if !strings.Contains(info, `"kind":"ExecCredential"`) || !strings.Contains(info, `"apiVersion":"client.authentication.k8s.io/v1"`) {
			fmt.Fprintln(os.Stderr, "credential helper received no ExecCredential context")
			os.Exit(2)
		}
		fmt.Print(`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"fixture"}}`)
	case "kubectl":
		helperKubectl(args)
	case "herdr":
		helperHerdr(t, args)
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

func readHerdrFixture(t *testing.T, path string) herdrFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state herdrFixture
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func helperHerdr(t *testing.T, args []string) {
	path := os.Getenv("FAKE_HERDR_STATE")
	state := readHerdrFixture(t, path)
	save := func() {
		if err := saveJSON(path, state); err != nil {
			t.Fatal(err)
		}
	}
	joined := strings.Join(args, " ")
	if joined == "machine list --json" {
		if err := json.NewEncoder(os.Stdout).Encode(state.Machines); err != nil {
			t.Fatal(err)
		}
		return
	}
	if len(args) >= 2 && args[0] == "machine" && args[1] == "add" {
		if os.Getenv("FAKE_HERDR_FAIL_ADD") == "1" {
			fmt.Fprintln(os.Stderr, "error: remote platform detection failed: agent@host: Permission denied (publickey).")
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

func (h harness) retainedHomes(t *testing.T) []RetainedHome {
	t.Helper()
	homes, err := listRetainedHomes(h.stateDir)
	if err != nil {
		t.Fatal(err)
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
	api := &fixtureAPI{t: t, sandboxes: map[string]*fixtureSandbox{}, failDelete: map[string]int{}}
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

func TestCLIAdoptsIdentityAfterFailedConnection(t *testing.T) {
	h := newHarness(t)
	second := filepath.Join(t.TempDir(), "id_ed25519_second")
	mustWrite(t, second, "second private key fixture\n", 0o600)
	resolved, err := resolveIdentityFile(second)
	if err != nil {
		t.Fatal(err)
	}

	failed := h.runWith(t, "FAKE_HERDR_FAIL_ADD=1", "sandbox", "create", "identity-retry", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed first connection", failed, 2, "", "herdr exited")
	connectionFile := h.connectionState("sandbox-identity-retry")
	assertConnectionPhase(t, connectionFile, connectionPrepared)

	retried := h.runWith(t, "FAKE_SANDBOX_HOME="+t.TempDir(), "sandbox", "create", "identity-retry", "--template", "dev-small", "--identity", second, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "identity switch after failure", retried, 0, "ready sandbox identity-retry", "")

	data, err := os.ReadFile(connectionFile)
	if err != nil {
		t.Fatal(err)
	}
	var connection Connection
	if json.Unmarshal(data, &connection) != nil {
		t.Fatal("invalid connection state")
	}
	if connection.SSH.IdentityFile != resolved {
		t.Fatalf("saved identity = %q; want %q", connection.SSH.IdentityFile, resolved)
	}

	connected := h.run(t, "sandbox", "create", "identity-retry", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "connected identity stays pinned", connected, 2, "", "is connected with identity file")
}

func TestCLIListsWithoutHerdrWhenNoProfileIsConnected(t *testing.T) {
	h := newHarness(t)
	failed := h.runWith(t, "FAKE_HERDR_FAIL_ADD=1", "sandbox", "create", "unregistered", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "failed connection", failed, 2, "", "herdr exited")

	listed := h.runWith(t, "KUBEFLOCK_HERDR=/nonexistent/herdr", "sandbox", "list", "--output", "json", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "list without herdr", listed, 0, `"state": "failed"`, "")
}

func TestCLIWarmStandbyDeletesItsExclusiveHome(t *testing.T) {
	h := newHarness(t)
	created := h.run(t, "sandbox", "create", "warm", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "warm create", created, 0, "ready sandbox warm", "")
	deleted := h.run(t, "sandbox", "delete", "warm", "--confirm", "warm", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "warm delete", deleted, 0, "permanently deleted sandbox dev/warm", "")
	if homes := h.retainedHomes(t); len(homes) != 0 {
		t.Fatalf("deleted workspace remains retained: %#v", homes)
	}
	state := h.api.state("warm")
	if state.claim || state.sandbox || !state.homeMissing || !state.volumeMissing {
		t.Fatalf("workspace deletion state: %#v", state)
	}
}

func TestCLIConnectionAndSandboxLifecycle(t *testing.T) {
	const sandboxUID = "sandbox-delayed"
	h := newHarness(t)

	assertCLI(t, "delete action", h.run(t, "sandbox", "delete-action"), 0, "", "")
	actionState := readHerdrFixture(t, h.herdrState)
	if !slices.Contains(actionState.PaneArgs, "delete") {
		t.Fatalf("delete action did not open its Herdr pane: %#v", actionState.PaneArgs)
	}

	created := h.run(t, "sandbox", "create", "delayed", "--template", "dev-small", "--identity", h.identity, "--timeout", "2s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "create", created, 0, "ready sandbox delayed", "")
	assertConnectionPhase(t, h.connectionState(sandboxUID), connectionConnected)

	disconnected := h.run(t, "sandbox", "disconnect", "delayed")
	assertCLI(t, "disconnect", disconnected, 0, "remote processes are still running", "")
	assertCLI(t, "reconnect", h.run(t, "sandbox", "reconnect", "delayed", "--kubeconfig", h.kubeconfig), 0, "", "")
	stopped := h.run(t, "sandbox", "stop", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "stop", stopped, 0, "persistent home retained", "")
	resumed := h.run(t, "sandbox", "resume", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "resume", resumed, 0, "connected as kubeflock-sandbox-delayed", "")

	declined := h.run(t, "sandbox", "delete", "delayed", "--confirm", "wrong", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "declined delete", declined, 2, "Permanently delete sandbox dev/delayed", "nothing was deleted")
	if state := h.api.state("delayed"); !state.claim || !state.sandbox || state.homeMissing {
		t.Fatalf("declined deletion changed workspace: %#v", state)
	}

	h.api.setHomeOwned("delayed", false)
	unknownOwner := h.run(t, "sandbox", "delete", "delayed", "--confirm", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "unknown home owner", unknownOwner, 2, "", "sandbox home home-delayed was replaced")
	h.api.setHomeOwned("delayed", true)

	deleted := h.run(t, "sandbox", "delete", "delayed", "--confirm", "delayed", "--timeout", "1s", "--kubeconfig", h.kubeconfig)
	assertCLI(t, "permanent delete", deleted, 0, "permanently deleted sandbox dev/delayed and its workspace data", "")
	state := h.api.state("delayed")
	if state.claim || state.sandbox || !state.homeMissing || !state.volumeMissing {
		t.Fatalf("workspace deletion state: %#v", state)
	}
	if homes := h.retainedHomes(t); len(homes) != 0 {
		t.Fatalf("deleted workspace remains retained: %#v", homes)
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

func assertConnectionPhase(t *testing.T, path string, want connectionPhase) {
	t.Helper()
	connection, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Phase != want {
		t.Fatalf("%s phase = %q; want %q", path, connection.Phase, want)
	}
}
