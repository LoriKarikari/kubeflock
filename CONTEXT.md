# Kubeflock

Kubeflock provides persistent agent workspaces on Kubernetes and connects them to Herdr. Compute, connection, and home storage have separate lifetimes.

## Language

### Allocation and capacity

**Target**:
The saved Kubernetes context and developer namespace in which a user works. It is independent of the workstation's currently selected Kubernetes context.
_Avoid_: Current cluster, default namespace

**Sandbox**:
An agent environment with managed compute and a persistent home. Its allocation name need not match the name of its backing compute resource, especially when supplied by a warm standby.
_Avoid_: Pod, container, connection

**SandboxClaim**:
An allocation request that binds a sandbox from a warm pool. The claim and the bound sandbox are distinct resources with separate identities.
_Avoid_: Sandbox, home

**Approved template**:
An administrator-provided definition of the sandbox environment that meets Kubeflock's runtime, security, and persistent-home requirements.
_Avoid_: Image, user-supplied Pod

**Warm pool**:
A source of sandboxes based on an approved template, optionally holding unclaimed standbys ready for allocation.
_Avoid_: Active sandbox list

**Warm standby**:
An unclaimed sandbox reserved for a future allocation. It consumes both compute and storage capacity before a user claims it.
_Avoid_: Stopped sandbox, retained home

**Compute budget**:
The total compute capacity shared by claimed sandboxes and warm standbys.
_Avoid_: Per-user quota

**Storage budget**:
The total home-storage capacity shared by claimed sandboxes, warm standbys, and retained homes.
_Avoid_: Active sandbox limit

### Connection and storage lifetimes

**Connection**:
The saved SSH identity, host-key pin, and Herdr registration used to access a sandbox. It is separate from the lifetime of the sandbox's compute and home.
_Avoid_: Sandbox, remote process

**Disconnect**:
Detaching the Herdr connection while leaving the sandbox and its remote processes running.
_Avoid_: Stop, delete

**Stop**:
Suspending a sandbox's compute while preserving its allocation and persistent home.
_Avoid_: Disconnect, delete

**Resume**:
Returning a stopped sandbox to running compute with its existing home and reconnecting it to Herdr.
_Avoid_: Restore, recreate home

**Persistent home**:
The sandbox's durable workspace containing project files, history, settings, and any attached credentials. Its identity is independent of the current compute instance.
_Avoid_: Container filesystem, local checkout

**Retained home**:
A persistent home preserved after its sandbox allocation is deleted, with provenance needed for restoration or permanent deletion. It continues to consume storage capacity.
_Avoid_: Backup, snapshot, stopped sandbox

**Delete sandbox**:
Removing the sandbox allocation and compute while retaining its home.
_Avoid_: Permanent deletion, delete home

**Restore**:
Attaching a retained home to a replacement allocation under its original allocation name and compatible approved template. Restoration preserves the home's identity and credential selection.
_Avoid_: Resume, clone, restore backup

**Delete home**:
Permanent removal of retained home storage, confirmed by its exact PVC UID. This is distinct from deleting a sandbox.
_Avoid_: Cleanup, disconnect

### Credentials and trust

**Approved credential**:
An administrator-defined alias for a Secret key in the target namespace and the environment variable it supplies. The alias is not the credential value or a per-key authorization boundary.
_Avoid_: Workstation credential, copied SSH key

**Developer namespace**:
The shared trust boundary for sandbox users authorized there. Those users may access each other's sandbox processes and homes; separate users require separate namespaces when that access is unacceptable.
_Avoid_: Per-sandbox isolation, Helm release namespace
