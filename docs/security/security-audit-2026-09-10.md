# Kubeflock security audit

Date: 2026-09-10
Revision audited: `aedff8f` (`feat/restore-home`, PR 23 head)

## Scope

Source-level audit of everything in this repository that crosses a trust boundary.

- CLI and library: `cmd/kubeflock/main.go`, `internal/kubeflock/*.go` (about 3,500 lines of non-test Go).
- Chart: `charts/kubeflock` (RBAC, namespace labels, budgets, SandboxTemplate, NetworkPolicy, values schema).
- Sandbox image: `sandbox-image/Dockerfile`, `sandbox-image/entrypoint.sh`.
- Plugin manifest `herdr-plugin.toml` and CI at `.github/workflows/ci.yml`.
- Dependencies in `go.mod`, scanned with `govulncheck`.

Trust boundaries considered: the local workstation (state directory, `~/.ssh`, identity files), the Kubernetes API and the objects it returns, the Agent Sandbox controller and its labels, the Sandbox pod (an untrusted workload by assumption, since an agent runs inside it), the container image supply chain, and other users in the same namespace.

Not in scope: the Agent Sandbox controller, gVisor, the Kubernetes API server, the storage backend, the npm registry, Herdr's own trust model, and live-cluster penetration testing. Every finding below is from source reading or a local reproduction.

## Method and evidence

- Read every production file in full, plus the chart templates, the image build, the plugin manifest, and CI.
- `govulncheck ./...` (status: 4 reachable vulnerabilities, 12 more in imported packages that the tool could not reach).
- Two reproductions written as throwaway tests in `internal/kubeflock`, run with `go test`, then deleted. Their code is inlined below so a reviewer can paste them back.
- Scanned all 13 commits for private keys and token patterns. Result: clean.
- Checked the `KUBECONFIG` environment versus `--kubeconfig` precedence end to end by spawning a child process. Result: the child sees the flag value, which is the safe outcome.
- `gofmt`, `go vet`, `golangci-lint`, `go test`, `go test -race`, and `helm lint` all pass on the audited revision, so nothing below is a hidden build or test failure.

## Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| F1 | Medium | Template hardening gate ignores privileged containers, init containers, host namespaces, and hostPath volumes | Confirmed by reproduction |
| F2 | Medium | Four reachable dependency vulnerabilities (denial of service) | Confirmed by `govulncheck` |
| F3 | Medium | One namespace with several subjects is a mutual-trust boundary | Confirmed by reading chart RBAC |
| F4 | Low | Sandbox image installs Pi from npm without integrity pinning | Confirmed by reading Dockerfile |
| F5 | Low | State-file paths are trusted for deletion and rewrite | Confirmed by reading code |
| F6 | Low | A symlinked `~/.ssh/config` is replaced by a regular file | Confirmed by reproduction |
| F7 | Low | SSH config values are not protected against control characters | Confirmed by reading code |

No high-severity findings. The destructive and ownership safety model is strong: every mutation carries a UID and resourceVersion precondition, deletes use orphan propagation, and no code path issues a PVC delete.

## F1. Template hardening gate bypass (Medium)

Locations: `internal/kubeflock/kube.go:269` (`validateTemplate`), `:285` (`podHardened`), `:298` (`containerHardened`).

`validateTemplate` is the gate that decides whether a SandboxTemplate is approved. A user-supplied template that passes it gets a claim, a sandbox with the template's image, and a connection. The gate checks the runtime class, the service-account token automount, pod and container security contexts, seccomp, dropped capabilities, and resource requests and limits. It does not check the following:

- `SecurityContext.Privileged` on any container. It is never read.
- `InitContainers`. The loop at `kube.go:275` only walks `podTemplate.spec.containers`.
- `HostNetwork`, `HostPID`, `HostIPC`.
- `hostPath` volumes, and any volume other than the home PVC.
- `Capabilities.Add`, `ReadOnlyRootFilesystem`, `ProcMount`, projected service-account tokens, and ephemeral containers.

Reproduction (passes on `aedff8f`, meaning the gate approves all of it):

```go
func TestAuditPrivilegedMainContainerPassesGate(t *testing.T) {
	container := auditHardenedContainer()
	container.SecurityContext.Privileged = ptr.To(true) // ignored by containerHardened
	pod := auditPod()
	pod.Containers = []corev1.Container{container}
	pod.Volumes = []corev1.Volume{{Name: "home", VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "home"}}}}
	if _, err := validateTemplate(auditTemplate(pod), "pool"); err != nil {
		t.Fatalf("privileged container was rejected: %v", err)
	}
}

func TestAuditUnhardenedInitContainerPassesGate(t *testing.T) {
	pod := auditPod()
	pod.InitContainers = []corev1.Container{{
		Name:            "setup",
		Image:           "evil:1",
		SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
		VolumeMounts:    []corev1.VolumeMount{{Name: "node", MountPath: "/host"}},
	}}
	pod.Containers = []corev1.Container{auditHardenedContainer()}
	pod.HostNetwork = true
	pod.Volumes = append(pod.Volumes,
		corev1.Volume{Name: "node", VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
	if _, err := validateTemplate(auditTemplate(pod), "pool"); err != nil {
		t.Fatalf("unhardened init container was rejected: %v", err)
	}
}
```

`auditPod` supplies the fields the gate already requires (gvisor runtime class, automount disabled, non-root UID 1000, seccomp RuntimeDefault) and `auditHardenedContainer` supplies an otherwise hardened main container with the SSH port, the home mount, and resource requests and limits.

Impact. Anyone who can create or patch a SandboxTemplate in the target namespace, or an operator who vendors a template from elsewhere, can run code that the gate is supposed to refuse. The gVisor runtime class still bounds the damage because gVisor does not honour most host kernel privileges, but a `hostPath: /` mount exposes host files readable by UID 1000, and the resource, capability, and hardening guarantees that the gate exists to enforce are gone. The CLI reports the template as approved, which is the part that misleads a user.

Recommendation. Make the gate exhaustive and fail closed.

- Reject `Privileged`, `Capabilities.Add`, and `ProcMount` on every container.
- Walk `InitContainers` and `EphemeralContainers` with the same checks.
- Reject `HostNetwork`, `HostPID`, `HostIPC`, and `ShareProcessNamespace`.
- Allow only the home PVC volume, and reject `hostPath`, `hostProcess`, projected service-account tokens, and `nfs` or `csi` volume sources unless explicitly intended.
- Convert the reproduction into a table test that asserts each rejected field, so the gate cannot regress.

## F2. Reachable dependency vulnerabilities (Medium)

Evidence, `govulncheck ./...` on `aedff8f`:

```text
Vulnerability #1: GO-2026-5970  golang.org/x/text@v0.31.0   fixed in v0.39.0
  Infinite loop on invalid input, reached from kube.go:645 (PVC Get) via norm.Form.Bytes
Vulnerability #2: GO-2026-5026  golang.org/x/net@v0.47.0    fixed in v0.55.0
  Punycode label handling, reached from kube.go:645 via idna.ToASCII
Vulnerability #3: GO-2026-5018  golang.org/x/crypto@v0.44.0 fixed in v0.52.0
  Pathological RSA/DSA parameters cause DoS, reached from connection.go:387 (normalizeHostKey)
Vulnerability #4: GO-2026-4918  golang.org/x/net@v0.47.0    fixed in v0.53.0
  HTTP/2 SETTINGS_MAX_FRAME_SIZE infinite loop, reached from kube.go:645 via http2.Transport
```

All four are denial of service, not disclosure or escalation, and all four are reachable from inputs the process already treats as untrusted. The x/net traces are reached while talking to the API server, so a hostile or compromised endpoint, or a hostile DNS name from a kubeconfig, can hang the CLI. The x/crypto trace is reached by `normalizeHostKey` parsing the contents of a file inside the Sandbox pod, and the Sandbox content is attacker-influenced by definition, since an agent runs there. Note that the type check for ed25519 happens after the parse, so a non-ed25519 pathological key still hits the vulnerable parser.

Recommendation. Upgrade the three modules and re-run `govulncheck`.

```bash
go get golang.org/x/crypto@v0.52.0 golang.org/x/net@v0.55.0 golang.org/x/text@v0.39.0
go mod tidy
govulncheck ./...
```

Add `govulncheck` to `just verify` or to the CI workflow so the next reachable vulnerability fails the build instead of waiting for the next audit. That is the structural fix for this class.

## F3. Namespace subjects share full sandbox access (Medium, operator-facing)

Locations: `charts/kubeflock/templates/rbac.yaml:24` (`pods/exec` create), `:27` (`persistentvolumeclaims` patch), `:9` (`sandboxes` get, patch, delete), values schema `access.subjects` (an array with `minItems: 1`).

The Role is namespace-scoped and is granted to every subject listed in `access.subjects`, and the example values file shows one User. Nothing stops an operator from listing several users or a whole group. A subject of this Role can do all of the following inside the namespace:

- `pods/exec` create on any pod in the namespace, which is a full read and write of another user's running sandbox and its mounted home.
- `patch` on any PersistentVolumeClaim, with no `resourceNames` limit. Together with `sandboxclaims` create and the `agents.x-k8s.io/adoptable` label that Kubeflock sets at `kube.go:510`, a second tenant can label an unowned retained PVC and claim it under the matching name, taking the data.
- `delete` on any Sandbox and `delete` on any SandboxClaim, which destroys another tenant's compute.

So a shared namespace is a shared trust domain, and the chart does not say so. A second user in the same values file is a silent cross-user data exposure, because the operator is likely reading `access.subjects` as "people who may use Kubeflock", not "people who may read each other's files".

Recommendation.

- State the rule in `charts/kubeflock/README.md` and in the values schema description: every subject of one release shares full read and write access to every Sandbox and home in that namespace. Use one namespace per user or per mutually trusting group.
- Consider a chart-time guard for the common mistake, such as a `fail` when the subject list contains more than one distinct user or a broad group.
- If per-user isolation is required, the namespace must be per user, because `pods/exec` alone defeats in-namespace separation.

## F4. Pi is installed from npm without integrity pinning (Low)

Location: `sandbox-image/Dockerfile:37`.

The base image is pinned by digest and the Herdr binary is verified with a hardcoded SHA-256, which is good. The Pi coding agent is installed with `npm install --global "@earendil-works/pi-coding-agent@${PI_VERSION}"` and no integrity hash or lockfile. A compromised registry response, a hijacked maintainer account, or a republished version injects code that runs as the agent inside every sandbox, next to the home volume that holds provider credentials.

Recommendation. Install from a URL with a recorded integrity hash, or vendor a lockfile.

```dockerfile
RUN curl -fsSL "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-${PI_VERSION}.tgz" -o /tmp/pi.tgz \
 && echo "${PI_SHA512}  /tmp/pi.tgz" | sha512sum --check \
 && npm install --global /tmp/pi.tgz
```

## F5. State-file paths are trusted for deletion and rewrite (Low)

Locations: `internal/kubeflock/connection.go:151` (`removeConnection`), `:185` (`removeSSHInclude`).

`removeConnection` unlinks `connection.SSH.KnownHostsFile`, `EntryFile`, `ProxyFile`, and the state file path, all read from the JSON record on disk. `removeSSHInclude` reads and rewrites `connection.SSH.ConfigFile` with the same provenance. A tampered or hand-edited record therefore turns `kubeflock sandbox delete` or `disconnect` into an arbitrary unlink and an arbitrary file rewrite with the user's file permissions, for example `~/.ssh/id_ed25519` or a shell profile.

Reachability is local only, since the state directory is created `0700` and files `0600`, so a second user on the workstation cannot write the record. It is still a cheap guard against a privileged mistake and against future code that accepts a record from elsewhere.

Recommendation. Before any unlink or rewrite, require that each path resolves under the connection state directory or the sibling `ssh` directory, and refuse otherwise. Keep the existing `owns` check for Herdr profiles, which already rejects a profile that does not match its identity.

## F6. A symlinked `~/.ssh/config` is replaced by a regular file (Low)

Location: `internal/kubeflock/connection.go:402` (`ensureSSHFiles`), calling `atomicWrite`, which uses `renameio`.

Reproduction on `aedff8f`:

```go
real := filepath.Join(dir, "dotfiles-ssh-config")
link := filepath.Join(dir, "ssh-config")
os.WriteFile(real, []byte("Host unrelated\n"), 0o600)
os.Symlink(real, link)
atomicWrite(link, []byte("Include \"/x\"\n"), 0o600)
// Result: link is now a regular file, mode 0600, content "Include \"/x\"\n".
// The dotfiles target still contains "Host unrelated\n".
```

A user who manages `~/.ssh/config` as a symlink into a dotfiles repository silently loses the link. Later edits in the repository stop reaching the live config, and the file that carries the Kubeflock include is no longer the one the user edits. This is a data-integrity issue with a confusing failure mode rather than an escalation.

Recommendation. Resolve the config path with `filepath.EvalSymlinks` before writing, or refuse a symlinked config with a clear error that names the file. The identity file already goes through `EvalSymlinks` at `connection.go:326`, so the pattern exists in the codebase.

## F7. SSH config quoting ignores control characters (Low)

Location: `internal/kubeflock/connection.go:394` (`sshQuote`) and the `Host` line in `ensureSSHFiles`.

`sshQuote` escapes `%`, `\`, and `"`, which covers the OpenSSH expansion and quoting rules but not `\n` or `\r`. The alias is interpolated into `Host %s` with no quoting at all. Today the alias is `kubeflock-` plus a Kubernetes UID, which is a UUID, and the paths come from the local user's `--identity` argument or from the state file. So this is self-inflicted input only, and not remotely reachable.

Recommendation. Reject `\n` and `\r` in `IdentityFile`, `ConfigFile`, and the alias, and require the identity path to be absolute and a regular file after resolution. Two lines of validation close the whole class.

## Verified controls

These were examined and found sound. They are listed so the coverage is auditable, not as praise.

- Destructive operations. Every patch and delete carries `metadata.uid` and `metadata.resourceVersion` preconditions, or a delete precondition UID. Claim and Sandbox deletes use orphan propagation so nothing cascades. Grep across the repository finds no `Delete` call on PersistentVolumeClaims. `preventHomeReAdoption` clears both Agent Sandbox labels before an orphan delete.
- Ownership and identity. Home PVCs are verified by UID, owner reference, and capacity shape before attachment. Herdr profiles are verified by label, target alias, and session before enable, disable, or remove. Refusals outnumber guesses.
- Input validation. Sandbox and template names go through `validation.IsDNS1123Label`. `--home` is matched against local records and never used to build a path. The config decoder sets `KnownFields(true)` and the state decoder sets `RejectUnknownMembers(true)`.
- Cluster data handling. Objects are decoded into typed structs and then field-checked (name, UID, warm pool non-empty). No cluster-provided string reaches a shell. All process execution is `execve` with an argument vector.
- Process handling. Commands run in their own process group with a SIGKILL cancellation and a `WaitDelay`, and `commandError` never echoes stderr into user-facing errors, so a credential helper cannot leak a secret through an error message.
- Credentials. The kubeconfig exec plugin is invoked once, its token or client certificate is kept in memory, and `auth.Exec` is cleared so the library cannot invoke it again. Nothing is written to disk. The SSH private key is referenced by path in the ssh config and never copied into the cluster, which the entrypoint confirms by deriving `authorized_keys` from a public key environment variable.
- SSH. `StrictHostKeyChecking yes`, `IdentitiesOnly yes`, a per-sandbox known-hosts file, and a host key that is parsed and re-marshalled as a single ed25519 key with no trailing data. The proxy script is written `0700` and quotes the executable path.
- RBAC. The ClusterRole grants exactly three reads, two of them with `resourceNames` (`runtimeclasses/gvisor`, `namespaces/<target>`). No secrets access, no pod create, no PVC delete. The chart's `values.schema.json` constrains names, the image pull policy, the SSH port, the key prefix, and every numeric field.
- Namespace defaults. Pod Security Admission `restricted` on all three modes, a ResourceQuota covering pods, PVCs, CPU, memory, and storage, a LimitRange with defaults, and a default-deny ingress NetworkPolicy.
- Supply chain. The base image is a digest, the Herdr binary is checksummed, all four GitHub Actions are pinned to commit SHAs, CI runs with `contents: read` and no `pull_request_target`, and the full git history contains no keys or tokens.
- Local state. Files are written through `renameio` at `0600`, directories are created `0700`, so an interrupted write cannot leave a half-parsed record and a second user cannot read the records.

## Out of scope and open questions

- No live-cluster testing was done. The audit is source and local reproduction only. The findings in F1 and F3 could be re-verified against a real cluster with a hostile template and a second test user.
- The Agent Sandbox controller's adoption rules are taken as given. F3 assumes the label is sufficient to adopt an unowned PVC, which the project's own fixture simulates but which this audit did not test against the real controller.
- gVisor's actual containment of a privileged container with a `hostPath: /` mount bounds the impact of F1 and was not measured here.
- No fuzzing of `normalizeHostKey` or of the state and config decoders. Given F2, a fuzz pass over the host key parser would be cheap.
- The `.scratch` or release pipeline outside CI is not audited, and image signing or provenance attestation is not in place.

## Remediation

Fix commits below landed on this branch after the audit. The audited revision was `aedff8f`.

| ID | Status | Change |
|----|--------|--------|
| F1 | Fixed | `b4e2abf` hardens the gate and adds a table test for every rejected field |
| F2 | Fixed | `8183c9a` updates the three modules, `042cc56` adds a `vuln` recipe and a CI job |
| F3 | Fixed | `e4f40aa` documents the shared trust domain and refuses broad groups |
| F4 | Accepted | No change, reasoning below |
| F5 | Fixed | `ecfc0aa` confines removal to the state directories |
| F6 | Fixed | `ecfc0aa` follows a symlinked ssh config instead of replacing it |
| F7 | Fixed | `ecfc0aa` rejects control characters in the saved ssh state |

F4 was deliberately left alone. Two fixes were built and discarded. A committed npm lockfile pins all 165 transitive packages but adds two files, one of them 87 KB, and a regeneration step on every Pi upgrade. A sha512-pinned tarball URL in the Dockerfile adds four lines and was rejected as machinery this finding does not earn. The version is already pinned exactly, so a compromised future release cannot reach the image, and an operator who needs byte-level control pins the built image by digest in `sandbox.image`, which the chart already documents. Revisit if the registry threat model changes.

Still open from the audit: live-cluster verification of F1 and F3 against the real controller, fuzzing for `normalizeHostKey` and the state decoders, and image signing or provenance attestation.
