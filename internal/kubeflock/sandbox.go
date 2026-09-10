package kubeflock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	sandboxapi "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsapi "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
)

// ponytail: failure guessed from condition text; upgrade path is the controller's condition reason taxonomy
var failedReason = regexp.MustCompile(`(?i)error|fail|invalid|forbidden|quota|unschedulable|conflict|not.?found|multiple`)

type claimProgress struct {
	State       string
	Step        string
	Message     string
	SandboxName string
}

func progress(claim extensionsapi.SandboxClaim) claimProgress {
	ready := meta.FindStatusCondition(claim.Status.Conditions, "Ready")
	detail := "waiting for the Sandbox controller"
	if ready != nil {
		detail = ready.Reason
		if ready.Message != "" {
			if detail != "" {
				detail += ": "
			}
			detail += ready.Message
		}
		if detail == "" {
			detail = "waiting for the Sandbox controller"
		}
	}
	if ready != nil && ready.Status == metav1.ConditionTrue && claim.Status.SandboxStatus.Name != "" {
		return claimProgress{State: "ready", SandboxName: claim.Status.SandboxStatus.Name}
	}
	if ready != nil && ready.Status == metav1.ConditionFalse && failedReason.MatchString(detail) {
		return claimProgress{State: "failed", Step: "readiness", Message: detail}
	}
	return claimProgress{State: "provisioning", Step: "readiness", Message: detail}
}

type sandboxOperatingMode = sandboxapi.SandboxOperatingMode

const (
	modeRunning   = sandboxapi.SandboxOperatingModeRunning
	modeSuspended = sandboxapi.SandboxOperatingModeSuspended
)

func normalizedMode(mode sandboxOperatingMode) sandboxOperatingMode {
	if mode == "" {
		return modeRunning
	}
	return mode
}

type projectRequest struct {
	Repository string
	Branch     string
}

type createOptions struct {
	Template     string
	IdentityFile string
	Project      *projectRequest
	Credentials  []string
	Timeout      time.Duration
	Poll         time.Duration
	Global       globalOptions
}

type lifecycleOptions struct {
	Timeout time.Duration
	Poll    time.Duration
	Global  globalOptions
}

type lifecycleResult struct {
	Name     string
	SSHAlias string
}

type retainResult struct {
	Name string
	Home PersistentHome
}

type createdSandbox struct {
	Name        string
	Template    string
	WarmPool    string
	SSHAlias    string
	Home        PersistentHome
	Project     *projectRequest
	Checkout    error
	Credentials int
}

type restoreSelection struct {
	Retained RetainedHome
	Approved approvedTemplate
}

type homeDeletionSelection struct {
	Retained RetainedHome
	Volume   *PersistentVolume
}

func selectManaged(target KubeTarget, name, stateDir string) (*ManagedSandbox, error) {
	saved, err := listManagedSandboxes(stateDir)
	if err != nil {
		return nil, err
	}
	var match *ManagedSandbox
	for i := range saved {
		claim := saved[i].Claim
		if claim.Context != target.Context || claim.Namespace != target.Namespace || (name != "" && saved[i].allocationName() != name) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple saved sandboxes match %s/%s", target.Namespace, name)
		}
		match = &saved[i]
	}
	return match, nil
}

func verifySandboxRunning(ctx context.Context, client *kubeClient, target KubeTarget, name string, claim extensionsapi.SandboxClaim) error {
	if claim.Status.SandboxStatus.Name == "" {
		return nil
	}
	sandbox, err := client.getSandboxIfExists(ctx, target, claim.Status.SandboxStatus.Name, "")
	if err != nil {
		return err
	}
	if sandbox == nil || !controlledBy(sandbox.OwnerReferences, claim.UID) {
		return nil
	}
	if normalizedMode(sandbox.Spec.OperatingMode) == modeSuspended {
		return fmt.Errorf("sandbox %s/%s is stopped; run: kubeflock sandbox resume %s", target.Namespace, name, name)
	}
	return nil
}

func applyOperatingMode(ctx context.Context, client *kubeClient, target KubeTarget, sandbox *sandboxapi.Sandbox, connection *savedConnection, mode sandboxOperatingMode, options lifecycleOptions) error {
	if mode == modeSuspended {
		if err := disableMachine(ctx, connection); err != nil {
			return fmt.Errorf("detach Herdr connection: %w", err)
		}
	}
	if err := client.setOperatingMode(ctx, target, sandbox, mode); err != nil {
		return err
	}
	identity := SandboxIdentity{
		Context:   target.Context,
		Namespace: sandbox.Namespace,
		Name:      sandbox.Name,
		UID:       string(sandbox.UID),
	}
	return waitForOperatingMode(ctx, client, target, identity, mode, options.Timeout, options.Poll)
}

func verifyBound(target KubeTarget, managed *ManagedSandbox) error {
	if managed.Phase != managedBound || managed.Sandbox == nil || managed.Home == nil {
		return fmt.Errorf("sandbox %s/%s has no complete saved resource identity", target.Namespace, managed.allocationName())
	}
	return nil
}

// verifySavedIdentity refuses an identity change once a sandbox holds a connected Herdr
// profile. Before that point the saved file is a first attempt, not a decision.
func verifySavedIdentity(target KubeTarget, stateDir, identity string, saved *ManagedSandbox) error {
	if saved == nil || saved.IdentityFile == identity {
		return nil
	}
	pinned, locked, err := connectedIdentity(stateDir, saved)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("saved sandbox %s/%s is connected with identity file %s; delete it before switching identities", target.Namespace, saved.allocationName(), pinned)
	}
	return nil
}

func connectedIdentity(stateDir string, saved *ManagedSandbox) (string, bool, error) {
	if saved == nil || saved.Sandbox == nil {
		return "", false, nil
	}
	connection, err := loadConnection(filepath.Join(stateDir, saved.Sandbox.UID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if connection.Phase != connectionConnected {
		return "", false, nil
	}
	return connection.SSH.IdentityFile, true, nil
}

func savedConnectionFor(target KubeTarget, stateDir string, sandbox SandboxIdentity) (*savedConnection, error) {
	connection, err := selectConnection(&target, stateDir, sandbox.Name)
	if err != nil {
		return nil, err
	}
	if connection != nil && connection.Connection.Sandbox.UID != sandbox.UID {
		return nil, errors.New("saved connection uses a different sandbox identity")
	}
	return connection, nil
}

func verifyClaim(claim *extensionsapi.SandboxClaim, target KubeTarget, name, warmPool string, saved *ManagedSandbox) error {
	if claim.Labels[managedByLabel] != managedByValue {
		return fmt.Errorf("SandboxClaim %s/%s is not managed by Kubeflock", target.Namespace, name)
	}
	if claim.Spec.WarmPoolRef.Name != warmPool {
		return fmt.Errorf("SandboxClaim %s/%s uses warm pool %s, not %s", target.Namespace, name, claim.Spec.WarmPoolRef.Name, warmPool)
	}
	if saved != nil && string(claim.UID) != saved.Claim.UID {
		return fmt.Errorf("SandboxClaim %s/%s was replaced: expected UID %s, found %s", target.Namespace, name, saved.Claim.UID, claim.UID)
	}
	return nil
}

func verifyClaimHome(claim *extensionsapi.SandboxClaim, home *corev1.PersistentVolumeClaim) error {
	if home == nil {
		return nil
	}
	claims := claim.Spec.VolumeClaimTemplates
	if len(claims) == 1 && claims[0].Name == home.Name && reflect.DeepEqual(claims[0].Spec, home.Spec) {
		return nil
	}
	return fmt.Errorf("SandboxClaim %s/%s uses unexpected home templates", claim.Namespace, claim.Name)
}

func obtainClaim(ctx context.Context, client *kubeClient, target KubeTarget, name, warmPool string, home *corev1.PersistentVolumeClaim) (*extensionsapi.SandboxClaim, error) {
	claim, err := client.getClaim(ctx, target.Namespace, name)
	if err != nil {
		return nil, err
	}
	if claim != nil {
		return claim, nil
	}
	claim, createErr := client.createClaim(ctx, target, name, warmPool, home)
	if createErr == nil {
		return claim, nil
	}
	claim, err = client.getClaim(ctx, target.Namespace, name)
	if err == nil && claim != nil {
		return claim, nil
	}
	return nil, createErr
}

func waitForReady(ctx context.Context, client *kubeClient, target KubeTarget, name string, claim *extensionsapi.SandboxClaim, timeout, poll time.Duration) (string, error) {
	latest := progress(*claim)
	err := wait.PollUntilContextTimeout(ctx, poll, timeout, true, func(ctx context.Context) (bool, error) {
		latest = progress(*claim)
		if latest.State == "ready" {
			return true, nil
		}
		if latest.State == "failed" {
			return false, fmt.Errorf("sandbox failed during %s: %s", latest.Step, latest.Message)
		}
		// A stopped sandbox reports the same not-ready claim as one still provisioning.
		if err := verifySandboxRunning(ctx, client, target, name, *claim); err != nil {
			return false, err
		}
		next, err := client.getClaim(ctx, target.Namespace, claim.Name)
		if err != nil {
			return false, err
		}
		if next == nil {
			return false, fmt.Errorf("SandboxClaim %s/%s disappeared during provisioning", target.Namespace, claim.Name)
		}
		if next.UID != claim.UID {
			return false, fmt.Errorf("SandboxClaim %s/%s was replaced during provisioning", target.Namespace, claim.Name)
		}
		claim = next
		return false, nil
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", fmt.Errorf("sandbox provisioning timed out during %s: %s", latest.Step, latest.Message)
		}
		return "", err
	}
	return latest.SandboxName, nil
}

func createSandbox(ctx context.Context, target KubeTarget, name string, restore *restoreSelection, options createOptions) (createdSandbox, error) {
	identity, creationLock, err := prepareCreation(target, name, options)
	if err != nil {
		return createdSandbox{}, err
	}
	defer func() { _ = creationLock.Unlock() }()
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return createdSandbox{}, err
	}
	var retained *RetainedHome
	if restore == nil {
		found, err := retainedHomeForOrigin(target, name, options.Global.StateDir)
		if err != nil {
			return createdSandbox{}, err
		}
		if found != nil {
			return createdSandbox{}, fmt.Errorf("retained home %s occupies the storage name for sandbox %s; select it explicitly with --home %s or choose a new sandbox name", found.Home.Name, name, found.Home.UID)
		}
	} else {
		found, err := selectRetainedHome(target, restore.Retained.Home.UID, options.Global.StateDir)
		if err != nil {
			return createdSandbox{}, err
		}
		if !reflect.DeepEqual(*found, restore.Retained) {
			return createdSandbox{}, errors.New("selected retained home changed before attachment; review it and retry")
		}
		retained = found
	}
	if restore != nil {
		switch {
		case len(options.Credentials) == 0:
			options.Credentials = slices.Clone(restore.Retained.Credentials)
		case len(restore.Retained.Credentials) > 0 && !sameCredentials(restore.Retained.Credentials, options.Credentials):
			return createdSandbox{}, fmt.Errorf("retained home %s keeps credentials %s; restore it with the same selection", restore.Retained.Home.Name, strings.Join(restore.Retained.Credentials, ", "))
		}
	}
	selected, err := client.selectCredentials(ctx, target.Namespace, options.Credentials)
	if err != nil {
		if restore != nil && len(restore.Retained.Credentials) > 0 {
			return createdSandbox{}, fmt.Errorf("retained home %s keeps credentials %s: %w", restore.Retained.Home.Name, strings.Join(restore.Retained.Credentials, ", "), err)
		}
		return createdSandbox{}, err
	}
	approved, err := client.resolveApprovedTemplate(ctx, target.Namespace, options.Template)
	if err != nil {
		return createdSandbox{}, err
	}
	claimName := name
	var claimHome *corev1.PersistentVolumeClaim
	if restore != nil {
		if approved.ResourceVersion != restore.Approved.ResourceVersion || approved.Image != restore.Approved.Image {
			return createdSandbox{}, errors.New("selected SandboxTemplate changed before attachment; review it and retry")
		}
		claimName, claimHome = retained.Origin.Name, &approved.Home
		allowedSandboxUID, err := validateRestoreResources(ctx, client, target, name, claimName, identity, *retained, approved, options.Global.StateDir)
		if err != nil {
			return createdSandbox{}, err
		}
		if err := client.authorizeHomeAdoption(ctx, target, retained.Home, allowedSandboxUID); err != nil {
			return createdSandbox{}, fmt.Errorf("authorize retained home adoption: %w", err)
		}
		retained.State = retainedHomeRestoring
		if err := saveJSON(retainedHomePath(options.Global.StateDir, retained.Home.UID), retained); err != nil {
			return createdSandbox{}, err
		}
	}
	managed, claim, err := ensureManagedSandbox(ctx, client, target, name, claimName, identity, options.Credentials, approved, claimHome, options.Global.StateDir)
	if err != nil {
		return createdSandbox{}, err
	}
	sandboxName, err := waitForReady(ctx, client, target, name, claim, options.Timeout, options.Poll)
	if err != nil {
		return createdSandbox{}, err
	}
	expected := ""
	if managed.Sandbox != nil {
		expected = managed.Sandbox.UID
	}
	resolved, err := client.resolveSandbox(ctx, target, sandboxName, expected)
	if err != nil {
		return createdSandbox{}, err
	}
	home, err := client.resolveHome(ctx, target, resolved.Identity, approved.Home.Name)
	if err != nil {
		return createdSandbox{}, err
	}
	if retained != nil && home.UID != retained.Home.UID {
		return createdSandbox{}, fmt.Errorf("sandbox %s attached unexpected home UID %s", name, home.UID)
	}
	if err := saveManagedBinding(managed, identity, resolved.Identity, home, options.Global.StateDir, string(claim.UID)); err != nil {
		return createdSandbox{}, err
	}
	credentials, err := client.readCredentials(ctx, target.Namespace, selected)
	if err != nil {
		return createdSandbox{}, err
	}
	if err := installCredentials(ctx, target, resolved, credentials, options); err != nil {
		return createdSandbox{}, err
	}
	connection, err := connect(ctx, target, connectOptions{
		Name:         resolved.Identity.Name,
		Label:        name,
		ExpectedUID:  resolved.Identity.UID,
		IdentityFile: identity,
		Global:       options.Global,
	})
	if err != nil {
		return createdSandbox{}, err
	}
	if retained != nil {
		if err := os.Remove(retainedHomePath(options.Global.StateDir, retained.Home.UID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return createdSandbox{}, err
		}
	}
	created := createdSandbox{Name: name, Template: approved.Name, WarmPool: approved.WarmPool, Home: home, SSHAlias: connection.SSH.Alias, Credentials: len(credentials)}
	if options.Project != nil {
		created.Project = options.Project
		created.Checkout = checkoutProject(ctx, target, resolved, *options.Project, options)
	}
	return created, nil
}

func checkoutProject(ctx context.Context, target KubeTarget, sandbox resolvedSandbox, project projectRequest, options createOptions) error {
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	args := []string{"--context", target.Context, "--namespace", target.Namespace, "exec", sandbox.Pod, "-c", sandbox.Container, "--", "git", "clone"}
	if project.Branch != "" {
		args = append(args, "--branch", project.Branch, "--single-branch")
	}
	args = append(args, "--", project.Repository, "/home/agent/project")
	if _, err := runKubectl(ctx, options.Global, args...); err != nil {
		if command, ok := errors.AsType[*commandError](err); ok && !command.TimedOut {
			if detail := strings.TrimSpace(command.Stderr); detail != "" {
				err = errors.New(detail)
			}
		}
		return fmt.Errorf("remote git clone: %w", err)
	}
	return nil
}

func saveManagedBinding(managed *ManagedSandbox, identity string, sandbox SandboxIdentity, home PersistentHome, stateDir, claimUID string) error {
	if managed.Phase == managedBound {
		if managed.Home == nil || managed.Home.UID != home.UID {
			return fmt.Errorf("sandbox home %s was replaced", home.Name)
		}
		if managed.IdentityFile == identity {
			return nil
		}
		managed.IdentityFile = identity
		return saveJSON(managedSandboxPath(stateDir, claimUID), managed)
	}
	managed.Phase, managed.Sandbox, managed.Home, managed.IdentityFile = managedBound, &sandbox, &home, identity
	return saveJSON(managedSandboxPath(stateDir, claimUID), managed)
}

func ensureManagedSandbox(ctx context.Context, client *kubeClient, target KubeTarget, name, claimName, identity string, credentials []string, approved approvedTemplate, home *corev1.PersistentVolumeClaim, stateDir string) (*ManagedSandbox, *extensionsapi.SandboxClaim, error) {
	saved, err := selectManaged(target, name, stateDir)
	if err != nil {
		return nil, nil, err
	}
	if saved != nil && (saved.Template != approved.Name || saved.WarmPool != approved.WarmPool) {
		return nil, nil, fmt.Errorf("saved sandbox %s/%s uses a different template or warm pool", target.Namespace, name)
	}
	if err := verifySavedIdentity(target, stateDir, identity, saved); err != nil {
		return nil, nil, err
	}
	if saved != nil && !sameCredentials(saved.Credentials, credentials) {
		return nil, nil, fmt.Errorf("saved sandbox %s/%s uses a different credential selection", target.Namespace, name)
	}
	claim, err := obtainClaim(ctx, client, target, claimName, approved.WarmPool, home)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyClaim(claim, target, claimName, approved.WarmPool, saved); err != nil {
		return nil, nil, err
	}
	if err := verifyClaimHome(claim, home); err != nil {
		return nil, nil, err
	}
	if saved != nil {
		return saved, claim, nil
	}
	managed := &ManagedSandbox{
		Version: 1,
		Phase:   "claimed",
		Name:    name,
		Claim: SandboxIdentity{
			Context:   target.Context,
			Namespace: target.Namespace,
			Name:      claimName,
			UID:       string(claim.UID),
		},
		Template:     approved.Name,
		WarmPool:     approved.WarmPool,
		IdentityFile: identity,
		Credentials:  slices.Clone(credentials),
	}
	if err := saveJSON(managedSandboxPath(stateDir, string(claim.UID)), managed); err != nil {
		return nil, nil, err
	}
	return managed, claim, nil
}

func inspectRestore(ctx context.Context, target KubeTarget, name, homeUID string, options createOptions) (restoreSelection, error) {
	identity, err := validateCreation(name, options)
	if err != nil {
		return restoreSelection{}, err
	}
	retained, err := selectRetainedHome(target, homeUID, options.Global.StateDir)
	if err != nil {
		return restoreSelection{}, err
	}
	if retained.State == retainedHomeDeleting {
		return restoreSelection{}, fmt.Errorf("retained home %s is being permanently deleted", retained.Home.Name)
	}
	if name != retained.allocationName() {
		return restoreSelection{}, fmt.Errorf("retained home %s can only be restored as sandbox %s", retained.Home.Name, retained.allocationName())
	}
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return restoreSelection{}, err
	}
	approved, err := client.resolveApprovedTemplate(ctx, target.Namespace, options.Template)
	if err != nil {
		return restoreSelection{}, err
	}
	if retained.Template != approved.Name || retained.WarmPool != approved.WarmPool {
		return restoreSelection{}, fmt.Errorf("retained home %s requires template %s and warm pool %s", retained.Home.Name, retained.Template, retained.WarmPool)
	}
	if !approved.HomeOverrides {
		return restoreSelection{}, fmt.Errorf("SandboxTemplate %s does not permit retained home restoration", approved.Name)
	}
	if _, err := validateRestoreResources(ctx, client, target, name, retained.Origin.Name, identity, *retained, approved, options.Global.StateDir); err != nil {
		return restoreSelection{}, err
	}
	return restoreSelection{Retained: *retained, Approved: approved}, nil
}

func validateRestoreResources(ctx context.Context, client *kubeClient, target KubeTarget, name, resourceName, identity string, retained RetainedHome, approved approvedTemplate, stateDir string) (string, error) {
	saved, err := selectManaged(target, name, stateDir)
	if err != nil {
		return "", err
	}
	if saved != nil {
		if saved.Template != approved.Name || saved.WarmPool != approved.WarmPool {
			return "", fmt.Errorf("saved sandbox %s/%s uses different restore settings", target.Namespace, name)
		}
		if err := verifySavedIdentity(target, stateDir, identity, saved); err != nil {
			return "", err
		}
		if saved.Home != nil && saved.Home.UID != retained.Home.UID {
			return "", fmt.Errorf("saved sandbox %s/%s uses a different home", target.Namespace, name)
		}
	}
	claim, err := client.getClaim(ctx, target.Namespace, resourceName)
	if err != nil {
		return "", err
	}
	if claim != nil && (saved == nil || string(claim.UID) != saved.Claim.UID) {
		return "", fmt.Errorf("SandboxClaim %s/%s belongs to another allocation", target.Namespace, resourceName)
	}
	sandbox, err := client.getSandboxIfExists(ctx, target, resourceName, "")
	if err != nil {
		return "", err
	}
	allowedSandboxUID := ""
	if sandbox != nil {
		switch {
		case saved == nil:
			return "", fmt.Errorf("sandbox %s/%s belongs to another allocation", target.Namespace, name)
		case saved.Sandbox != nil && saved.Sandbox.UID != string(sandbox.UID):
			return "", fmt.Errorf("sandbox %s/%s belongs to another allocation", target.Namespace, name)
		case saved.Sandbox == nil && (claim == nil || !controlledBy(sandbox.OwnerReferences, claim.UID)):
			return "", fmt.Errorf("sandbox %s/%s belongs to another allocation", target.Namespace, name)
		}
		allowedSandboxUID = string(sandbox.UID)
	}
	if err := client.verifyRestorableHome(ctx, target, resourceName, retained.Home, approved.Home, allowedSandboxUID); err != nil {
		return "", err
	}
	return allowedSandboxUID, nil
}

func validateProject(project *projectRequest) error {
	if project.Repository == "" {
		return errors.New("a project branch requires --repository")
	}
	if strings.ContainsAny(project.Repository+project.Branch, "\r\n\x00") {
		return errors.New("repository and branch must not contain control characters")
	}
	if parsed, err := url.Parse(project.Repository); err == nil && parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return errors.New("repository URL must not contain a password; configure authentication inside the sandbox")
		}
	}
	if strings.Contains(project.Repository, "?") {
		return errors.New("repository URL must not contain a query string; configure authentication inside the sandbox")
	}
	return nil
}

func validateCreation(name string, options createOptions) (string, error) {
	if options.Project != nil {
		if err := validateProject(options.Project); err != nil {
			return "", err
		}
	}
	if len(validation.IsDNS1123Label(name)) != 0 {
		return "", fmt.Errorf("invalid sandbox name %q", name)
	}
	if len(validation.IsDNS1123Label(options.Template)) != 0 {
		return "", fmt.Errorf("invalid template name %q", options.Template)
	}
	if options.IdentityFile == "" {
		return "", errors.New("specify --identity for sandbox creation")
	}
	return resolveIdentityFile(options.IdentityFile)
}

func prepareCreation(target KubeTarget, name string, options createOptions) (string, *flock.Flock, error) {
	identity, err := validateCreation(name, options)
	if err != nil {
		return "", nil, err
	}
	lock, err := acquireSandboxLock(target, name, options.Global.StateDir)
	return identity, lock, err
}

func acquireSandboxLock(target KubeTarget, name, stateDir string) (*flock.Flock, error) {
	locks := filepath.Join(stateDir, "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(target.Context + "\x00" + target.Namespace + "\x00" + name))
	lock := flock.New(filepath.Join(locks, hex.EncodeToString(key[:])))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("sandbox %s/%s already has a storage operation in progress", target.Namespace, name)
	}
	return lock, nil
}

func inspectRetainedHomeDeletion(ctx context.Context, target KubeTarget, uid string, options lifecycleOptions) (homeDeletionSelection, error) {
	retained, err := selectRetainedHome(target, uid, options.Global.StateDir)
	if err != nil {
		return homeDeletionSelection{}, err
	}
	if retained.State == retainedHomeRestoring {
		return homeDeletionSelection{}, fmt.Errorf("retained home %s is being restored", retained.Home.Name)
	}
	if retained.State == retainedHomeDeleting {
		return homeDeletionSelection{Retained: *retained, Volume: retained.Deletion}, nil
	}
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return homeDeletionSelection{}, err
	}
	volume, err := client.inspectHomeDeletion(ctx, target, *retained)
	if err != nil {
		return homeDeletionSelection{}, err
	}
	return homeDeletionSelection{Retained: *retained, Volume: volume}, nil
}

func deleteRetainedHome(ctx context.Context, target KubeTarget, uid string, options lifecycleOptions) error {
	retained, err := selectRetainedHome(target, uid, options.Global.StateDir)
	if err != nil {
		return err
	}
	lock, err := acquireSandboxLock(target, retained.allocationName(), options.Global.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()
	retained, err = selectRetainedHome(target, uid, options.Global.StateDir)
	if err != nil {
		return err
	}
	if retained.State == retainedHomeRestoring {
		return fmt.Errorf("retained home %s is being restored", retained.Home.Name)
	}
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return err
	}
	if retained.State == retainedHomeAvailable {
		volume, err := client.inspectHomeDeletion(ctx, target, *retained)
		if err != nil {
			return err
		}
		if volume != nil && volume.ReclaimPolicy != "Delete" {
			return fmt.Errorf("persistent volume %s uses %s reclaim policy; refusing because Kubernetes cannot confirm permanent storage deletion", volume.Name, volume.ReclaimPolicy)
		}
		retained.State, retained.Deletion = retainedHomeDeleting, volume
		if err := saveJSON(retainedHomePath(options.Global.StateDir, uid), retained); err != nil {
			return err
		}
	} else if err := client.verifyPendingHomeDeletion(ctx, target, *retained); err != nil {
		return err
	}
	if retained.State != retainedHomeDeleting || (retained.Deletion != nil && retained.Deletion.ReclaimPolicy != "Delete") {
		return fmt.Errorf("retained home %s has invalid deletion state", retained.Home.Name)
	}
	if err := client.deleteHomePVC(ctx, target, retained.Home); err != nil {
		return fmt.Errorf("delete retained home PVC: %w; deletion remains pending for %s", err, deletionTarget(retained.Home, retained.Deletion))
	}
	err = wait.PollUntilContextTimeout(ctx, options.Poll, options.Timeout, true, func(ctx context.Context) (bool, error) {
		return client.homeDeletionComplete(ctx, target, retained.Home, retained.Deletion)
	})
	if err != nil {
		return fmt.Errorf("deletion remains pending for %s: %w", deletionTarget(retained.Home, retained.Deletion), err)
	}
	if err := os.Remove(retainedHomePath(options.Global.StateDir, uid)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func deletionTarget(home PersistentHome, volume *PersistentVolume) string {
	if volume == nil {
		return "PVC " + home.Name
	}
	return fmt.Sprintf("PVC %s and PV %s", home.Name, volume.Name)
}

func changeSandboxMode(ctx context.Context, target KubeTarget, name string, mode sandboxOperatingMode, options lifecycleOptions) (lifecycleResult, error) {
	managed, err := selectManaged(target, name, options.Global.StateDir)
	if err != nil {
		return lifecycleResult{}, err
	}
	if managed == nil {
		return lifecycleResult{}, errors.New("no saved Kubeflock sandbox matches this target")
	}
	if err := verifyBound(target, managed); err != nil {
		return lifecycleResult{}, err
	}
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return lifecycleResult{}, err
	}
	claim, err := client.getClaim(ctx, target.Namespace, managed.Claim.Name)
	if err != nil {
		return lifecycleResult{}, err
	}
	if claim == nil {
		return lifecycleResult{}, fmt.Errorf("saved SandboxClaim %s/%s is missing", target.Namespace, managed.Claim.Name)
	}
	if err := verifyClaim(claim, target, managed.Claim.Name, managed.WarmPool, managed); err != nil {
		return lifecycleResult{}, err
	}
	if claim.Status.SandboxStatus.Name != managed.Sandbox.Name {
		return lifecycleResult{}, fmt.Errorf("SandboxClaim %s/%s is bound to unexpected Sandbox %s", target.Namespace, managed.Claim.Name, claim.Status.SandboxStatus.Name)
	}
	sandbox, err := client.getSandbox(ctx, target, managed.Sandbox.Name, managed.Sandbox.UID)
	if err != nil {
		return lifecycleResult{}, err
	}
	if _, err := client.ownedHome(ctx, target, *managed.Sandbox, *managed.Home); err != nil {
		return lifecycleResult{}, err
	}
	connection, err := savedConnectionFor(target, options.Global.StateDir, *managed.Sandbox)
	if err != nil {
		return lifecycleResult{}, err
	}
	if err := applyOperatingMode(ctx, client, target, sandbox, connection, mode, options); err != nil {
		return lifecycleResult{}, err
	}
	if _, err := client.ownedHome(ctx, target, *managed.Sandbox, *managed.Home); err != nil {
		return lifecycleResult{}, err
	}
	result := lifecycleResult{Name: managed.allocationName()}
	if mode == modeRunning {
		connection, err := connect(ctx, target, connectOptions{
			Name:         managed.Sandbox.Name,
			ExpectedUID:  managed.Sandbox.UID,
			IdentityFile: managed.IdentityFile,
			Global:       options.Global,
		})
		if err != nil {
			return lifecycleResult{}, fmt.Errorf("attach Herdr connection: %w", err)
		}
		result.SSHAlias = connection.SSH.Alias
	}
	return result, nil
}

func retainSandboxHome(ctx context.Context, target KubeTarget, name string, options lifecycleOptions) (retainResult, error) {
	managed, err := selectManaged(target, name, options.Global.StateDir)
	if err != nil {
		return retainResult{}, err
	}
	if managed == nil {
		return retainResult{}, errors.New("no saved Kubeflock sandbox matches this target")
	}
	if err := verifyBound(target, managed); err != nil {
		return retainResult{}, err
	}
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return retainResult{}, err
	}
	claim, err := client.getClaim(ctx, target.Namespace, managed.Claim.Name)
	if err != nil {
		return retainResult{}, err
	}
	sandbox, err := client.getSandboxIfExists(ctx, target, managed.Sandbox.Name, managed.Sandbox.UID)
	if err != nil {
		return retainResult{}, err
	}
	if claim != nil {
		if err := verifyClaim(claim, target, managed.Claim.Name, managed.WarmPool, managed); err != nil {
			return retainResult{}, err
		}
		if sandbox == nil || claim.Status.SandboxStatus.Name != managed.Sandbox.Name {
			return retainResult{}, errors.New("saved SandboxClaim no longer owns the expected Sandbox")
		}
	}
	connection, err := savedConnectionFor(target, options.Global.StateDir, *managed.Sandbox)
	if err != nil {
		return retainResult{}, err
	}
	if sandbox != nil {
		if _, err := client.ownedHome(ctx, target, *managed.Sandbox, *managed.Home); err != nil {
			return retainResult{}, err
		}
		if err := applyOperatingMode(ctx, client, target, sandbox, connection, modeSuspended, options); err != nil {
			return retainResult{}, err
		}
	}
	if claim != nil {
		if err := client.orphanDeleteClaim(ctx, target, managed.Claim); err != nil {
			return retainResult{}, fmt.Errorf("orphan Sandbox from claim: %w", err)
		}
		if err := waitForClaimDeletion(ctx, client, target, managed.Claim, options.Timeout, options.Poll); err != nil {
			return retainResult{}, err
		}
		if sandbox, err = client.getSandboxIfExists(ctx, target, managed.Sandbox.Name, managed.Sandbox.UID); err != nil {
			return retainResult{}, err
		}
		if sandbox == nil {
			return retainResult{}, errors.New("sandbox disappeared while its claim was orphan-deleted; refusing to continue")
		}
	}
	if sandbox != nil {
		if err := client.preventHomeReAdoption(ctx, target, *managed.Sandbox, *managed.Home); err != nil {
			return retainResult{}, fmt.Errorf("prevent controller re-adoption of home: %w", err)
		}
		if err := client.orphanDeleteSandbox(ctx, target, *managed.Sandbox); err != nil {
			return retainResult{}, fmt.Errorf("orphan home from Sandbox: %w", err)
		}
		if err := waitForSandboxDeletion(ctx, client, target, *managed.Sandbox, options.Timeout, options.Poll); err != nil {
			return retainResult{}, err
		}
	}
	if err := client.verifyRetainedHome(ctx, target, *managed.Sandbox, *managed.Home); err != nil {
		return retainResult{}, err
	}
	retained := RetainedHome{
		Version:     1,
		State:       retainedHomeAvailable,
		Name:        managed.allocationName(),
		Template:    managed.Template,
		WarmPool:    managed.WarmPool,
		Claim:       managed.Claim,
		Origin:      *managed.Sandbox,
		Home:        *managed.Home,
		Credentials: slices.Clone(managed.Credentials),
	}
	if err := saveJSON(retainedHomePath(options.Global.StateDir, managed.Home.UID), retained); err != nil {
		return retainResult{}, err
	}
	if err := removeConnection(ctx, connection); err != nil {
		return retainResult{}, fmt.Errorf("remove Herdr connection: %w", err)
	}
	if err := os.Remove(managedSandboxPath(options.Global.StateDir, managed.Claim.UID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return retainResult{}, err
	}
	return retainResult{Name: managed.allocationName(), Home: *managed.Home}, nil
}

func waitForClaimDeletion(ctx context.Context, client *kubeClient, target KubeTarget, identity SandboxIdentity, timeout, poll time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, poll, timeout, true, func(ctx context.Context) (bool, error) {
		claim, err := client.getClaim(ctx, target.Namespace, identity.Name)
		if err != nil {
			return false, err
		}
		if claim == nil {
			return true, nil
		}
		if string(claim.UID) != identity.UID {
			return false, fmt.Errorf("SandboxClaim %s/%s was replaced during deletion", target.Namespace, identity.Name)
		}
		return false, nil
	})
}

func waitForSandboxDeletion(ctx context.Context, client *kubeClient, target KubeTarget, identity SandboxIdentity, timeout, poll time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, poll, timeout, true, func(ctx context.Context) (bool, error) {
		sandbox, err := client.getSandboxIfExists(ctx, target, identity.Name, identity.UID)
		return sandbox == nil, err
	})
}

func waitForOperatingMode(ctx context.Context, client *kubeClient, target KubeTarget, identity SandboxIdentity, mode sandboxOperatingMode, timeout, poll time.Duration) error {
	conditionType := string(sandboxapi.SandboxConditionReady)
	if mode == modeSuspended {
		conditionType = string(sandboxapi.SandboxConditionSuspended)
	}
	latest := "waiting for the Sandbox controller"
	err := wait.PollUntilContextTimeout(ctx, poll, timeout, true, func(ctx context.Context) (bool, error) {
		sandbox, err := client.getSandbox(ctx, target, identity.Name, identity.UID)
		if err != nil {
			return false, err
		}
		if normalizedMode(sandbox.Spec.OperatingMode) != mode {
			return false, fmt.Errorf("sandbox %s/%s operating mode changed to %s", target.Namespace, identity.Name, normalizedMode(sandbox.Spec.OperatingMode))
		}
		condition := meta.FindStatusCondition(sandbox.Status.Conditions, conditionType)
		latest = conditionDetail(condition)
		if conditionObserved(condition, sandbox.Generation, metav1.ConditionFalse) && failedReason.MatchString(latest) {
			return false, fmt.Errorf("sandbox failed while entering %s mode: %s", mode, latest)
		}
		pods, err := client.ownedPods(ctx, target, sandbox)
		if err != nil {
			return false, err
		}
		observed := conditionObserved(condition, sandbox.Generation, metav1.ConditionTrue)
		if mode == modeSuspended {
			return observed && len(pods) == 0, nil
		}
		return observed && len(pods) == 1, nil
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("sandbox %s timed out while entering %s mode: %s", identity.Name, mode, latest)
	}
	return err
}

func conditionObserved(condition *metav1.Condition, generation int64, status metav1.ConditionStatus) bool {
	return condition != nil && condition.ObservedGeneration == generation && condition.Status == status
}

func conditionDetail(condition *metav1.Condition) string {
	if condition == nil {
		return "waiting for the Sandbox controller"
	}
	detail := condition.Reason
	if condition.Message != "" {
		if detail != "" {
			detail += ": "
		}
		detail += condition.Message
	}
	if detail == "" {
		return "waiting for the Sandbox controller"
	}
	return detail
}

func listSandboxStatus(ctx context.Context, target KubeTarget, options globalOptions) ([]SandboxStatus, error) {
	managedFiles, err := listManagedSandboxes(options.StateDir)
	if err != nil {
		return nil, err
	}
	managed := make([]ManagedSandbox, 0, len(managedFiles))
	for _, item := range managedFiles {
		claim := item.Claim
		if claim.Context == target.Context && claim.Namespace == target.Namespace {
			managed = append(managed, item)
		}
	}
	client, err := newKubeClient(ctx, target, options.Kubeconfig)
	if err != nil {
		return nil, err
	}
	claims, err := client.listClaims(ctx, target.Namespace)
	if err != nil {
		return nil, err
	}
	connections, err := listConnections(options.StateDir)
	if err != nil {
		return nil, err
	}
	machines := []herdrMachine{}
	if slices.ContainsFunc(connections, func(connection savedConnection) bool {
		return connection.Connection.Phase == connectionConnected
	}) {
		machines, err = listMachines(ctx)
		if err != nil {
			return nil, err
		}
	}
	suspended, err := client.suspendedSandboxes(ctx, target, managed)
	if err != nil {
		return nil, err
	}
	statuses := make([]SandboxStatus, 0, len(managed))
	for _, saved := range managed {
		statuses = append(statuses, sandboxStatus(saved, claims, connections, machines, suspended))
	}
	return statuses, nil
}

func sandboxStatus(saved ManagedSandbox, claims []extensionsapi.SandboxClaim, connections []savedConnection, machines []herdrMachine, suspended map[string]bool) SandboxStatus {
	status := SandboxStatus{
		Name:      saved.allocationName(),
		Namespace: saved.Claim.Namespace,
		ClaimUID:  saved.Claim.UID,
		Template:  saved.Template,
		WarmPool:  saved.WarmPool,
		Home:      saved.Home,
	}
	if saved.Sandbox != nil {
		status.SandboxUID = saved.Sandbox.UID
	}
	claim := slices.IndexFunc(claims, func(c extensionsapi.SandboxClaim) bool { return string(c.UID) == saved.Claim.UID })
	if claim < 0 {
		status.State, status.Step, status.Message = "failed", "claim", "saved SandboxClaim is missing"
		return status
	}
	if saved.Sandbox != nil && suspended[saved.Sandbox.UID] {
		status.State, status.Step, status.Message = "disconnected", "operating mode", "sandbox is stopped; run kubeflock sandbox resume "+saved.allocationName()
		return status
	}
	claimState := progress(claims[claim])
	if claimState.State != "ready" {
		status.State, status.Step, status.Message = claimState.State, claimState.Step, claimState.Message
		return status
	}
	if saved.Phase != managedBound || saved.Sandbox == nil {
		status.State, status.Step, status.Message = "provisioning", "connection", "waiting to record Sandbox and home identities"
		return status
	}
	connectionIndex := slices.IndexFunc(connections, func(c savedConnection) bool { return c.Connection.Sandbox.UID == saved.Sandbox.UID })
	if connectionIndex < 0 {
		status.State, status.Step, status.Message = "provisioning", "connection", "waiting for native Herdr registration"
		return status
	}
	connection := connections[connectionIndex].Connection
	if connection.Phase == connectionPrepared {
		status.State, status.Step, status.Message = "failed", "connection", "native Herdr registration did not complete"
		return status
	}
	machine := slices.IndexFunc(machines, func(m herdrMachine) bool { return m.ID == connection.ProfileID })
	switch {
	case machine < 0:
		status.State, status.Step, status.Message = "failed", "connection", "saved Herdr machine is missing"
	case machines[machine].Enabled:
		status.State = "ready"
	default:
		status.State = "disconnected"
	}
	return status
}
