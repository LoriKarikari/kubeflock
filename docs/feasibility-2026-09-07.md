# Feasibility checks

## Result

Herdr v0.9.0 native machine operations work through an OpenSSH ProxyCommand in an isolated Docker test. Disabling, enabling, and removing a profile preserved a running pane process. Adding an incompatible v0.7.4 server without an interactive terminal refused the upgrade and left the server unchanged.

After the user restored Omni login, API-only SSH passed against the existing gVisor sandbox as UID 1000. With approval, a separate cluster test then passed native Herdr v0.9.0 machine operations and file preservation through suspend/resume. The original sandboxes, quota, volumes, and workstation Herdr installation remain unchanged.

## Test setup

- Downloaded the official Herdr v0.9.0 Linux x86_64 release into `/tmp/kubeflock-feasibility`. Its SHA-256 matched GitHub's release digest, `4fa1a01158dd8043da92d31b270780b0dcc10603038d9b61cac4d81ab63fb71f`.
- Used separate temporary homes for the local client and two Docker fixtures. No workstation SSH or Herdr configuration changed.
- Both fixtures used the existing sandbox image at `sha256:955bbb837d9cd96b9a762fcb0385760ff5ac382f27fb8eeeda849e9fcd37f347`. One mounted the downloaded v0.9.0 binary read-only; the other kept its original v0.7.4 binary.
- Both ran as UID/GID 1000 with all capabilities dropped, no privilege escalation, no external network, and no published ports. These Docker tests did not use gVisor.
- Generated test-only SSH keys. Pinned each host key from its local test volume, without accepting unknown keys over SSH.
- Connected with `ProxyCommand docker exec -i CONTAINER socat STDIO TCP:127.0.0.1:2222`.

Release source: https://github.com/herdrdev/herdr/releases/tag/v0.9.0

## Approved Kubernetes test

Created namespace `kubeflock-check` with restricted PSS, deny-all ingress/egress, and a quota of one pod and one 1Gi PVC. Sandbox `native-check` uses gVisor, UID/GID 1000, no mounted service-account token, no added capabilities, no privilege escalation, and RuntimeDefault seccomp. Requests are 250m CPU and 512Mi memory; limits are one CPU and 1Gi memory.

The test uses the pinned 0.2 image and a separately verified Herdr v0.9.0 binary under the test home's `.local/bin`. It is a test fixture, not a published v0.9.0 sandbox image. Its home is an independently created PVC without a Sandbox owner reference, not a generated volumeClaimTemplate.

The SSH alias uses kubectl exec and socat through the API. Native Herdr added the saved machine for session `agent` without an installation prompt. A separate SSH connection stayed open for 35 seconds with multiplexing disabled. The test client uses an isolated HOME; only the kubectl transport uses the workstation kubeconfig and credential cache.

Ran a long-lived command in a Herdr pane. Disable, enable, and remove each preserved the same pane process, checked through its PID and `/proc` start time. Herdr's pane process-info response under gVisor omitted foreground-process details, so the test checked the actual process directly instead of treating missing metadata as process death. That metadata difference needs further investigation before claiming complete agent detection parity.

For storage, wrote a 64KiB random file, recorded its hash and the SSH host public-key hash, and recorded the PVC UID, PV name, and pod UID. Then:

1. Set operatingMode to Suspended and waited for pod deletion and the Suspended condition.
2. Confirmed the same PVC remained Bound to the same PV.
3. Set operatingMode to Running and waited for Ready.
4. Confirmed the replacement pod had a different UID.
5. Compared both hashes and the PVC/PV identities. All matched.
6. Added the native machine again through the API transport with the unchanged strict host-key pin. It succeeded.

Finally suspended the test sandbox again. No test pod remains. PVC `home`, UID `006b038d-6f06-4e4b-88a3-f4870f28562f`, remains Bound in `kubeflock-check`. Deleting it still needs separate approval. The original two pods both remain Running with zero restarts, and their original 10Gi PVCs remain Bound.

Evidence under `/tmp/kubeflock-feasibility`:

- `k8s-test.yaml`, the applied fixture.
- `k8s-check.sh` and `k8s-check.log`, the native-command test and passing output.
- `k8s-hashes-before.txt` and `k8s-hashes-after.txt`.
- `k8s-pvc-before.json`, `k8s-pvc-stopped.json`, and `k8s-pvc-after.json`.
- `k8s-pod-uid-before.txt` and `k8s-pod-uid-after.txt`.

This proves native CLI setup over the API and disk preservation through pod replacement. It does not exercise the local TUI, an actual AI provider, or claim/warm-pool lifecycle ownership. Safe deletion of controller-owned storage remains a separate design and test requirement.

## Native machines

The v0.9.0 client successfully added a saved machine for remote session `agent` with stdin closed. `machine list --json` reported the expected target, label, session, and enabled state. The remote status reported version 0.9.0, protocol 22, compatible endpoint capabilities, and no restart needed.

Created a remote workspace and ran `sleep 600` in a pane. After each of `machine disable`, `machine enable`, and `machine remove`, the test checked:

- The expected local profile state.
- The same pane and shell identities.
- The same foreground process PID, command, and process start time.

All assertions passed. The test did not exercise the local Herdr TUI or an actual AI provider.

The first add attempt failed during endpoint probing. Herdr's bootstrap used its managed SSH config, but the endpoint probe used plain OpenSSH. OpenSSH did not use the temporary HOME's config in that path. A test-only `ssh` wrapper supplied the isolated config to every invocation. The next add passed. Kubeflock's real SSH alias must be available to ordinary OpenSSH, not only to one bootstrap command.

Evidence:

- `/tmp/kubeflock-feasibility/check-native.py`
- `/tmp/kubeflock-feasibility/native-results.json`
- [Saved-machine preparation](https://github.com/herdrdev/herdr/blob/b99002ac99b09e00b4ca692436cb15a6b0d676f1/src/remote/attach.rs#L80-L138)
- [Endpoint probe](https://github.com/herdrdev/herdr/blob/b99002ac99b09e00b4ca692436cb15a6b0d676f1/src/remote/attach.rs#L1233-L1248)

## Upgrade approval

Attempted to add the v0.7.4 fixture from the v0.9.0 client with stdin closed. Herdr returned exit code 1:

```text
remote herdr server on kubeflock-old (session agent) is running v0.7.4; run from an interactive terminal to approve stopping it for the update; machine was not saved
```

Before and after, the test compared the installed version, binary hash, and server process start time. All matched. The client catalog remained empty.

This proves the refusal path for this version pair. It does not mean every version difference requires replacement. Herdr checks endpoint capabilities as well as versions.

Evidence:

- `/tmp/kubeflock-feasibility/check-approval.py`
- `/tmp/kubeflock-feasibility/approval-results.json`
- [Approval with a running server](https://github.com/herdrdev/herdr/blob/b99002ac99b09e00b4ca692436cb15a6b0d676f1/src/remote/attach.rs#L1084-L1197)

## API-only SSH

The tested ProxyCommand carries an SSH byte stream over Docker exec. The Kubernetes candidate replaces that transport with:

```sh
kubectl --context CONTEXT --namespace NAMESPACE exec -i POD -- \
  socat STDIO TCP:127.0.0.1:2222
```

This candidate needs no sandbox LoadBalancer or direct client-to-pod route. It still needs working Kubernetes API access and permission to exec into the pod. Exact RBAC verbs, credential refresh, reconnect behavior, and pod identity checks need a Kubernetes test.

The read-only cluster probes timed out, including a 12-second outer deadline around an 8-second kubectl request timeout. The diagnostic log showed kubeconfig loading but no API result. The selected context was `homelab`, with an OIDC exec credential helper.

Further checks found the immediate blocker. OIDC helper PID 184733, started by k9s PID 9242 at 22:53, held the token-cache write lock for over an hour. `lslocks` showed the test helpers waiting for that same lock. Their file descriptors showed the lock file but no network sockets. The cause of the k9s helper's own stall remains unknown.

The outer timeouts left six credential-helper processes behind. SIGTERM did not clear them; SIGKILL cleared those six test-owned helpers. A final lock check showed only the original k9s helper. The k9s session and its helper remained untouched. No token cache contents were read, copied, printed, or deleted.

After the user cleared the k9s blockage, the next lock check showed no OIDC lock holder. The API probe reached an interactive Omni authorization prompt, then exited with EOF because no authorization code could be entered through the unattended command. Cluster access now needs the user to complete that login in a terminal. No authorization URL or code belongs in these notes.

The retry used a separate process group and an outer deadline with process-group cleanup. Kubeflock will need a subprocess deadline that also cleans up credential-helper descendants. An API request timeout alone is not sufficient.

After login, verified Claim `dev-test-02` still had UID `4c84df64-dfff-41e5-a62c-6f540aa22e18` and pointed to pod `dev-small-kf4mv`. OpenSSH connected through kubectl exec and socat with strict host-key checking against the existing pin. Disabled SSH multiplexing so the test could not reuse a direct-network connection. Read-only remote commands returned UID 1000 and Herdr 0.7.4. Evidence is in `/tmp/kubeflock-feasibility/api-ssh-results.json`.

Verdict: API-only SSH passed on the original gVisor sandbox, without upgrading it. Native Herdr v0.9.0 also passed in the separately approved test namespace described above.

## Stop, resume, and deletion

Checked Agent Sandbox v1.0.1 at commit `3e77ccbac4db8a12b0157eafcad0d1ad5872f32a`.

`spec.operatingMode: Suspended` asks the controller to delete the owned pod while retaining the Sandbox and volumes. Setting it back to `Running` permits pod creation. The PVC controller reuses existing owned PVCs by name. Kubeflock must wait for observed suspension or readiness, not equate a successful patch with completion.

Sources:

- [Operating mode contract](https://github.com/kubernetes-sigs/agent-sandbox/blob/3e77ccbac4db8a12b0157eafcad0d1ad5872f32a/api/v1beta1/sandbox_types.go#L288-L299)
- [Suspension implementation](https://github.com/kubernetes-sigs/agent-sandbox/blob/3e77ccbac4db8a12b0157eafcad0d1ad5872f32a/controllers/sandbox_controller.go#L1246-L1277)
- [PVC reuse and ownership](https://github.com/kubernetes-sigs/agent-sandbox/blob/3e77ccbac4db8a12b0157eafcad0d1ad5872f32a/controllers/sandbox_controller.go#L1622-L1699)

Deletion needs more care. The controller gives generated PVCs a Sandbox controller owner reference. Plain deletion can therefore garbage-collect the stored home. Merely removing that reference in a separate step is not enough proof of safety: reconciliation can adopt a matching unowned PVC again.

The agreed separate storage-deletion confirmation remains a requirement. The deletion sequence must preserve storage ownership safely and pass crash/retry tests before we implement a delete command. A PVC byte-preservation test across suspend/resume also remains necessary.

The installed served v1beta1 CRD exposes `spec.operatingMode` with `Running` and `Suspended` values, matching the source contract. The `gvisor` RuntimeClass uses handler `runsc`. The approved cluster test verified file preservation through suspend/resume on an independently managed Longhorn PVC.

The existing namespace's `commissioning-lock` quota is full at two pods and two PVCs. Both 10Gi homes are Bound. A disposable test must use separately approved capacity rather than deleting either existing volume or relaxing that quota. The cluster offers `longhorn`, with Delete reclaim policy, and `longhorn-retain`, with Retain policy.

## Registration in the user's Herdr

The user upgraded the installed client and running local server to v0.9.0. On their request to continue, resumed `kubeflock-check/native-check` and registered it in the real Herdr catalog as `Kubeflock test`, profile `20987102b167ebb3564fb476f301e1c7`, SSH target `kubeflock-check`, session `agent`.

Test SSH files now live under `/home/lori/.config/kubeflock/ssh/check`. The private test key has mode 600. The host key came from the authenticated Kubernetes API. `/home/lori/.ssh/config` includes the test-specific config; comparing `ssh -G herdr-dev-test-02` before and after showed no change to the existing alias.

The remote status reported v0.9.0 and no restart needed. Native machine add succeeded and the real catalog lists the profile as enabled. The test sandbox is now running for the user to inspect in the sidebar. No visual confirmation from the user has been recorded yet.

## Cleanup and next checks

Removed only the two disposable Docker fixtures after recording results. Test files remain under `/tmp/kubeflock-feasibility`. At the end of the isolated checks, the workstation still used v0.7.4. The user later upgraded it to v0.9.0 as described above. No project commits or pushes occurred.

The approved namespace test covered API-only SSH, native setup after pod replacement, and file preservation through suspend/resume. The user later requested registration in their real Herdr, so it is now running with its 1Gi volume retained. Still open are controller-owned storage deletion, the full claim/warm-pool flow, local TUI behavior, and the missing foreground-process metadata under gVisor. No storage deletion or implementation work has approval from these test results alone.
