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
The sandbox's durable workspace containing project files, history, settings, and provider credentials saved by tools inside the sandbox. Its identity is independent of the current compute instance.
_Avoid_: Container filesystem, local checkout

**Retained home**:
Home storage left after its sandbox allocation is removed, either from the former retention workflow or while permanent deletion is incomplete. It continues to consume storage capacity; Kubeflock has no supported operation to restore it.
_Avoid_: Backup, snapshot, stopped sandbox

**Delete sandbox**:
Permanent removal of the sandbox allocation, compute, and workspace storage after explicit confirmation.
_Avoid_: Stop, disconnect, retain home

### Credentials and trust

**SSH identity**:
The workstation's private SSH key selected to connect to a sandbox. It is distinct from the public key authorized by the sandbox and from provider credentials.
_Avoid_: Provider credential, sandbox host key

**Provider credential**:
Authentication data obtained by a tool inside the sandbox, such as Pi, and potentially saved in the persistent home. Its lifetime follows that home when saved there.
_Avoid_: SSH identity, approved credential alias

**Developer namespace**:
The shared trust boundary for sandbox users authorized there. Those users may access each other's sandbox processes and homes; separate users require separate namespaces when that access is unacceptable.
_Avoid_: Per-sandbox isolation, Helm release namespace
