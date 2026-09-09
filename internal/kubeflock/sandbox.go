package kubeflock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/gofrs/flock"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
)

// ponytail: failure guessed from condition text; upgrade path is the controller's condition reason taxonomy
var failedReason = regexp.MustCompile(`(?i)error|fail|invalid|forbidden|quota|unschedulable|conflict|not.?found|multiple`)

type claimProgress struct {
	State       string
	Step        string
	Message     string
	SandboxName string
}

func progress(claim sandboxClaim) claimProgress {
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
	if ready != nil && ready.Status == metav1.ConditionTrue && claim.Status.Sandbox.Name != "" {
		return claimProgress{State: "ready", SandboxName: claim.Status.Sandbox.Name}
	}
	if ready != nil && ready.Status == metav1.ConditionFalse && failedReason.MatchString(detail) {
		return claimProgress{State: "failed", Step: "readiness", Message: detail}
	}
	return claimProgress{State: "provisioning", Step: "readiness", Message: detail}
}

type createOptions struct {
	Template     string
	IdentityFile string
	Timeout      time.Duration
	Poll         time.Duration
	Global       globalOptions
}

type createdSandbox struct {
	Name     string
	Template string
	WarmPool string
	SSHAlias string
	Home     PersistentHome
}

func selectManaged(target KubeTarget, name, stateDir string) (*ManagedSandbox, error) {
	saved, err := listManagedSandboxes(stateDir)
	if err != nil {
		return nil, err
	}
	var match *ManagedSandbox
	for i := range saved {
		claim := saved[i].Sandbox.Claim
		if claim.Context != target.Context || claim.Namespace != target.Namespace || claim.Name != name {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple saved sandboxes match %s/%s", target.Namespace, name)
		}
		match = &saved[i].Sandbox
	}
	return match, nil
}

func verifyClaim(claim *sandboxClaim, target KubeTarget, name, warmPool string, saved *ManagedSandbox) error {
	if claim.Metadata.Labels[managedByLabel] != managedByValue {
		return fmt.Errorf("SandboxClaim %s/%s is not managed by Kubeflock", target.Namespace, name)
	}
	if claim.Spec.WarmPoolRef.Name != warmPool {
		return fmt.Errorf("SandboxClaim %s/%s uses warm pool %s, not %s", target.Namespace, name, claim.Spec.WarmPoolRef.Name, warmPool)
	}
	if saved != nil && string(claim.Metadata.UID) != saved.Claim.UID {
		return fmt.Errorf("SandboxClaim %s/%s was replaced: expected UID %s, found %s", target.Namespace, name, saved.Claim.UID, claim.Metadata.UID)
	}
	return nil
}

func obtainClaim(ctx context.Context, client *kubeClient, target KubeTarget, name, warmPool string) (*sandboxClaim, error) {
	claim, err := client.getClaim(ctx, target.Namespace, name)
	if err != nil {
		return nil, err
	}
	if claim != nil {
		return claim, nil
	}
	claim, createErr := client.createClaim(ctx, target, name, warmPool)
	if createErr == nil {
		return claim, nil
	}
	claim, err = client.getClaim(ctx, target.Namespace, name)
	if err == nil && claim != nil {
		return claim, nil
	}
	return nil, createErr
}

func waitForReady(ctx context.Context, client *kubeClient, target KubeTarget, claim *sandboxClaim, timeout, poll time.Duration) (string, error) {
	latest := progress(*claim)
	err := wait.PollUntilContextTimeout(ctx, poll, timeout, true, func(ctx context.Context) (bool, error) {
		latest = progress(*claim)
		if latest.State == "ready" {
			return true, nil
		}
		if latest.State == "failed" {
			return false, fmt.Errorf("sandbox failed during %s: %s", latest.Step, latest.Message)
		}
		next, err := client.getClaim(ctx, target.Namespace, claim.Metadata.Name)
		if err != nil {
			return false, err
		}
		if next == nil {
			return false, fmt.Errorf("SandboxClaim %s/%s disappeared during provisioning", target.Namespace, claim.Metadata.Name)
		}
		if next.Metadata.UID != claim.Metadata.UID {
			return false, fmt.Errorf("SandboxClaim %s/%s was replaced during provisioning", target.Namespace, claim.Metadata.Name)
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

func createSandbox(ctx context.Context, target KubeTarget, name string, options createOptions) (createdSandbox, error) {
	identity, creationLock, err := prepareCreation(target, name, options)
	if err != nil {
		return createdSandbox{}, err
	}
	defer func() { _ = creationLock.Unlock() }()
	client, err := newKubeClient(ctx, target, options.Global.Kubeconfig)
	if err != nil {
		return createdSandbox{}, err
	}
	approved, err := client.resolveApprovedTemplate(ctx, target.Namespace, options.Template)
	if err != nil {
		return createdSandbox{}, err
	}
	managed, claim, err := ensureManagedSandbox(ctx, client, target, name, identity, approved, options.Global.StateDir)
	if err != nil {
		return createdSandbox{}, err
	}
	sandboxName, err := waitForReady(ctx, client, target, claim, options.Timeout, options.Poll)
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
	if sandboxName != name {
		return createdSandbox{}, fmt.Errorf("SandboxClaim %s/%s was bound to unexpected Sandbox %s", target.Namespace, name, sandboxName)
	}
	home, err := client.resolveHome(ctx, target, resolved.Identity, approved.HomeTemplate)
	if err != nil {
		return createdSandbox{}, err
	}
	if err := saveManagedBinding(managed, resolved.Identity, home, options.Global.StateDir, string(claim.Metadata.UID)); err != nil {
		return createdSandbox{}, err
	}
	connection, err := connect(ctx, target, connectOptions{
		Name:         name,
		ExpectedUID:  resolved.Identity.UID,
		IdentityFile: identity,
		Global:       options.Global,
	})
	if err != nil {
		return createdSandbox{}, err
	}
	return createdSandbox{Name: name, Template: approved.Name, WarmPool: approved.WarmPool, Home: home, SSHAlias: connection.SSH.Alias}, nil
}

func saveManagedBinding(managed *ManagedSandbox, sandbox SandboxIdentity, home PersistentHome, stateDir, claimUID string) error {
	if managed.Phase == "bound" {
		if managed.Home == nil || managed.Home.UID != home.UID {
			return fmt.Errorf("sandbox home %s was replaced", home.Name)
		}
		return nil
	}
	managed.Phase, managed.Sandbox, managed.Home = "bound", &sandbox, &home
	return saveJSON(managedSandboxPath(stateDir, claimUID), managed)
}

func ensureManagedSandbox(ctx context.Context, client *kubeClient, target KubeTarget, name, identity string, approved approvedTemplate, stateDir string) (*ManagedSandbox, *sandboxClaim, error) {
	saved, err := selectManaged(target, name, stateDir)
	if err != nil {
		return nil, nil, err
	}
	if saved != nil && (saved.Template != approved.Name || saved.WarmPool != approved.WarmPool) {
		return nil, nil, fmt.Errorf("saved sandbox %s/%s uses a different template or warm pool", target.Namespace, name)
	}
	if saved != nil && saved.IdentityFile != identity {
		return nil, nil, fmt.Errorf("saved sandbox %s/%s uses a different SSH identity file", target.Namespace, name)
	}
	claim, err := obtainClaim(ctx, client, target, name, approved.WarmPool)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyClaim(claim, target, name, approved.WarmPool, saved); err != nil {
		return nil, nil, err
	}
	if saved != nil {
		return saved, claim, nil
	}
	managed := &ManagedSandbox{
		Version: 1,
		Phase:   "claimed",
		Claim: SandboxIdentity{
			Context:   target.Context,
			Namespace: target.Namespace,
			Name:      name,
			UID:       string(claim.Metadata.UID),
		},
		Template:     approved.Name,
		WarmPool:     approved.WarmPool,
		IdentityFile: identity,
	}
	if err := saveJSON(managedSandboxPath(stateDir, string(claim.Metadata.UID)), managed); err != nil {
		return nil, nil, err
	}
	return managed, claim, nil
}

func prepareCreation(target KubeTarget, name string, options createOptions) (string, *flock.Flock, error) {
	if len(validation.IsDNS1123Label(name)) != 0 {
		return "", nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	if len(validation.IsDNS1123Label(options.Template)) != 0 {
		return "", nil, fmt.Errorf("invalid template name %q", options.Template)
	}
	if options.IdentityFile == "" {
		return "", nil, errors.New("specify --identity for sandbox creation")
	}
	identity, err := filepath.EvalSymlinks(options.IdentityFile)
	if err != nil {
		return "", nil, err
	}
	identity, err = filepath.Abs(identity)
	if err != nil {
		return "", nil, err
	}
	locks := filepath.Join(options.Global.StateDir, "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		return "", nil, err
	}
	key := sha256.Sum256([]byte(target.Context + "\x00" + target.Namespace + "\x00" + name))
	creationLock := flock.New(filepath.Join(locks, hex.EncodeToString(key[:])))
	locked, err := creationLock.TryLock()
	if err != nil {
		return "", nil, err
	}
	if !locked {
		return "", nil, fmt.Errorf("sandbox %s/%s is already being created", target.Namespace, name)
	}
	return identity, creationLock, nil
}

func listSandboxStatus(ctx context.Context, target KubeTarget, options globalOptions) ([]SandboxStatus, error) {
	managedFiles, err := listManagedSandboxes(options.StateDir)
	if err != nil {
		return nil, err
	}
	managed := make([]ManagedSandbox, 0, len(managedFiles))
	for _, item := range managedFiles {
		claim := item.Sandbox.Claim
		if claim.Context == target.Context && claim.Namespace == target.Namespace {
			managed = append(managed, item.Sandbox)
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
	machines, err := listMachines(ctx)
	if err != nil {
		return nil, err
	}
	statuses := make([]SandboxStatus, 0, len(managed))
	for _, saved := range managed {
		statuses = append(statuses, sandboxStatus(saved, claims, connections, machines))
	}
	return statuses, nil
}

func sandboxStatus(saved ManagedSandbox, claims []sandboxClaim, connections []savedConnection, machines []herdrMachine) SandboxStatus {
	status := SandboxStatus{
		Name:      saved.Claim.Name,
		Namespace: saved.Claim.Namespace,
		ClaimUID:  saved.Claim.UID,
		Template:  saved.Template,
		WarmPool:  saved.WarmPool,
		Home:      saved.Home,
	}
	if saved.Sandbox != nil {
		status.SandboxUID = saved.Sandbox.UID
	}
	claim := slices.IndexFunc(claims, func(c sandboxClaim) bool { return string(c.Metadata.UID) == saved.Claim.UID })
	if claim < 0 {
		status.State, status.Step, status.Message = "failed", "claim", "saved SandboxClaim is missing"
		return status
	}
	claimState := progress(claims[claim])
	if claimState.State != "ready" {
		status.State, status.Step, status.Message = claimState.State, claimState.Step, claimState.Message
		return status
	}
	if saved.Phase != "bound" || saved.Sandbox == nil {
		status.State, status.Step, status.Message = "provisioning", "connection", "waiting to record Sandbox and home identities"
		return status
	}
	connectionIndex := slices.IndexFunc(connections, func(c savedConnection) bool { return c.Connection.Sandbox.UID == saved.Sandbox.UID })
	if connectionIndex < 0 {
		status.State, status.Step, status.Message = "provisioning", "connection", "waiting for native Herdr registration"
		return status
	}
	connection := connections[connectionIndex].Connection
	if connection.Phase == "prepared" {
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
