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
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
)

// ponytail: failure guessed from condition text; upgrade path is the controller's condition reason taxonomy
var failedReason = regexp.MustCompile(`(?i)error|fail|invalid|forbidden|quota|unschedulable|conflict|not.?found|multiple`)

type claimProgress struct {
	State, Step, Message, SandboxName string
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
	Template, IdentityFile string
	Timeout, Poll          time.Duration
	Global                 globalOptions
}

type createdSandbox struct {
	Name, Template, WarmPool, SSHAlias string
	Home                               PersistentHome
}

func selectManaged(target KubeTarget, name, stateDir string) (*ManagedSandbox, error) {
	saved, err := listManagedSandboxes(stateDir)
	if err != nil {
		return nil, err
	}
	matches := lo.FilterMap(saved, func(item savedSandbox, _ int) (ManagedSandbox, bool) {
		claim := item.Sandbox.Claim
		return item.Sandbox, claim.Context == target.Context && claim.Namespace == target.Namespace && claim.Name == name
	})
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple saved sandboxes match %s/%s", target.Namespace, name)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return &matches[0], nil
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
	if len(validation.IsDNS1123Label(name)) != 0 {
		return createdSandbox{}, fmt.Errorf("invalid sandbox name %q", name)
	}
	if len(validation.IsDNS1123Label(options.Template)) != 0 {
		return createdSandbox{}, fmt.Errorf("invalid template name %q", options.Template)
	}
	if options.IdentityFile == "" {
		return createdSandbox{}, errors.New("specify --identity for sandbox creation")
	}
	identity, err := filepath.EvalSymlinks(options.IdentityFile)
	if err != nil {
		return createdSandbox{}, err
	}
	identity, err = filepath.Abs(identity)
	if err != nil {
		return createdSandbox{}, err
	}
	locks := filepath.Join(options.Global.StateDir, "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		return createdSandbox{}, err
	}
	key := sha256.Sum256([]byte(target.Context + "\x00" + target.Namespace + "\x00" + name))
	lock := filepath.Join(locks, hex.EncodeToString(key[:]))
	creationLock := flock.New(lock)
	locked, err := creationLock.TryLock()
	if err != nil {
		return createdSandbox{}, err
	}
	if !locked {
		return createdSandbox{}, fmt.Errorf("sandbox %s/%s is already being created", target.Namespace, name)
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
	saved, err := selectManaged(target, name, options.Global.StateDir)
	if err != nil {
		return createdSandbox{}, err
	}
	if saved != nil && (saved.Template != approved.Name || saved.WarmPool != approved.WarmPool) {
		return createdSandbox{}, fmt.Errorf("saved sandbox %s/%s uses a different template or warm pool", target.Namespace, name)
	}
	if saved != nil && saved.IdentityFile != identity {
		return createdSandbox{}, fmt.Errorf("saved sandbox %s/%s uses a different SSH identity file", target.Namespace, name)
	}
	claim, err := obtainClaim(ctx, client, target, name, approved.WarmPool)
	if err != nil {
		return createdSandbox{}, err
	}
	if err := verifyClaim(claim, target, name, approved.WarmPool, saved); err != nil {
		return createdSandbox{}, err
	}
	managed := saved
	if managed == nil {
		managed = &ManagedSandbox{Version: 1, Phase: "claimed", Claim: SandboxIdentity{Context: target.Context, Namespace: target.Namespace, Name: name, UID: string(claim.Metadata.UID)}, Template: approved.Name, WarmPool: approved.WarmPool, IdentityFile: identity}
		if err := saveJSON(managedSandboxPath(options.Global.StateDir, string(claim.Metadata.UID)), managed); err != nil {
			return createdSandbox{}, err
		}
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
	if managed.Phase == "bound" {
		if managed.Home == nil || managed.Home.UID != home.UID {
			return createdSandbox{}, fmt.Errorf("sandbox home %s was replaced", home.Name)
		}
	} else {
		managed.Phase, managed.Sandbox, managed.Home = "bound", &resolved.Identity, &home
		if err := saveJSON(managedSandboxPath(options.Global.StateDir, string(claim.Metadata.UID)), managed); err != nil {
			return createdSandbox{}, err
		}
	}
	connection, err := connect(ctx, target, connectOptions{Name: name, ExpectedUID: resolved.Identity.UID, IdentityFile: identity, Global: options.Global})
	if err != nil {
		return createdSandbox{}, err
	}
	return createdSandbox{Name: name, Template: approved.Name, WarmPool: approved.WarmPool, Home: home, SSHAlias: connection.SSH.Alias}, nil
}

func listSandboxStatus(ctx context.Context, target KubeTarget, options globalOptions) ([]SandboxStatus, error) {
	managedFiles, err := listManagedSandboxes(options.StateDir)
	if err != nil {
		return nil, err
	}
	managed := lo.FilterMap(managedFiles, func(item savedSandbox, _ int) (ManagedSandbox, bool) {
		claim := item.Sandbox.Claim
		return item.Sandbox, claim.Context == target.Context && claim.Namespace == target.Namespace
	})
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
		status := SandboxStatus{Name: saved.Claim.Name, Namespace: saved.Claim.Namespace, ClaimUID: saved.Claim.UID, Template: saved.Template, WarmPool: saved.WarmPool, Home: saved.Home}
		if saved.Sandbox != nil {
			status.SandboxUID = saved.Sandbox.UID
		}
		claim := slices.IndexFunc(claims, func(c sandboxClaim) bool { return string(c.Metadata.UID) == saved.Claim.UID })
		if claim < 0 {
			status.State, status.Step, status.Message = "failed", "claim", "saved SandboxClaim is missing"
			statuses = append(statuses, status)
			continue
		}
		claimState := progress(claims[claim])
		if claimState.State != "ready" {
			status.State, status.Step, status.Message = claimState.State, claimState.Step, claimState.Message
			statuses = append(statuses, status)
			continue
		}
		if saved.Phase != "bound" || saved.Sandbox == nil {
			status.State, status.Step, status.Message = "provisioning", "connection", "waiting to record Sandbox and home identities"
			statuses = append(statuses, status)
			continue
		}
		found := slices.IndexFunc(connections, func(c savedConnection) bool { return c.Connection.Sandbox.UID == saved.Sandbox.UID })
		if found < 0 {
			status.State, status.Step, status.Message = "provisioning", "connection", "waiting for native Herdr registration"
			statuses = append(statuses, status)
			continue
		}
		connection := connections[found].Connection
		if connection.Phase == "prepared" {
			status.State, status.Step, status.Message = "failed", "connection", "native Herdr registration did not complete"
			statuses = append(statuses, status)
			continue
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
		statuses = append(statuses, status)
	}
	return statuses, nil
}
