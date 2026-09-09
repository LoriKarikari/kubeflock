# Kubeflock

Kubeflock creates personal Kubernetes sandboxes and connects them to Herdr through native Herdr machines. Sandboxes run behind the Kubernetes API. They do not need a public SSH service or a direct network route from the workstation.

## Requirements

- Node.js 22.18 or newer
- Herdr 0.9.0 or newer
- A working kubeconfig
- Agent Sandbox `v1beta1` APIs
- The `gvisor` RuntimeClass
- A persistent StorageClass
- A namespace with ResourceQuota
- An administrator-defined `SandboxTemplate` and `SandboxWarmPool`
- Helm 3 for cluster setup

Install the CLI and link the Herdr plugin from this repository:

```bash
npm ci
npm run build
npm link
herdr plugin link .
```

## Configure the cluster target

Save the Kubernetes context and namespace that Kubeflock must use:

```bash
kubeflock cluster config --context homelab --namespace agent-sandboxes
```

Kubeflock saves this target. Changing the current kubectl context does not retarget Kubeflock.

Show the saved target:

```bash
kubeflock cluster config show
kubeflock cluster config show --output json
```

Check the cluster APIs, runtime, storage, quota, and permissions:

```bash
kubeflock cluster check
kubeflock cluster check --timeout 2m --output json
```

## Templates

A cluster administrator creates each template with Kubernetes manifests. A template fixes the image, compute budget, storage budget, runtime, security settings, home mount, and SSH environment.

The Kubeflock Helm chart creates a developer namespace, least-privilege access, quotas, a starter template, and its zero-replica warm pool. Copy and edit its values first:

```bash
cp charts/kubeflock/values.example.yaml values.yaml
helm template kubeflock charts/kubeflock \
  --namespace agent-sandboxes \
  --values values.yaml
helm upgrade --install kubeflock charts/kubeflock \
  --namespace agent-sandboxes \
  --create-namespace \
  --values values.yaml \
  --wait
```

See [`charts/kubeflock/README.md`](charts/kubeflock/README.md) for controller installation, GitOps rendering, access, budgets, and upgrades.

Each usable template has one `SandboxWarmPool` with the same namespace and a reference to the template. Kubeflock cold creation requires `spec.replicas: 0`.

Kubeflock accepts only templates that provide:

- `runtimeClassName: gvisor`
- UID and GID 1000
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `seccompProfile.type: RuntimeDefault`
- `automountServiceAccountToken: false`
- CPU and memory requests and limits
- SSH on container port 2222
- Persistent storage mounted at `/home/agent`
- A Herdr-compatible image and SSH configuration

Users select a template by name. They cannot override its image, resources, environment, or Pod specification during creation.

## Create a sandbox

Create a named sandbox and connect it to Herdr:

```bash
kubeflock sandbox create my-agent \
  --template dev-small \
  --identity ~/.ssh/id_ed25519
```

Kubeflock creates a `SandboxClaim`, waits for the controller to report readiness, records the Claim, Sandbox, and home PVC identities, pins the SSH host key, and registers one native Herdr machine.

A retry uses the saved identities. Kubeflock refuses a same-named replacement resource, a different template, a different SSH identity, or an unrelated Claim.

## List sandboxes

```bash
kubeflock sandbox list
kubeflock sandbox list --output json
```

Kubeflock reports these observed states:

- `provisioning` means the controller or native connection has not finished.
- `ready` means the Sandbox and Herdr machine are ready.
- `failed` includes the failed lifecycle step.
- `disconnected` means the Herdr machine is disabled while the Sandbox remains running.

## Connect an existing sandbox

Connect a ready Sandbox that already has a compatible persistent home and SSH environment:

```bash
kubeflock sandbox connect my-agent --identity ~/.ssh/id_ed25519
```

Reconnect a saved sandbox:

```bash
kubeflock sandbox reconnect my-agent
```

Disconnect it from Herdr:

```bash
kubeflock sandbox disconnect my-agent
```

Disconnecting disables the saved Herdr machine. It does not stop the Sandbox or its remote processes.

## Herdr actions

The plugin provides these actions:

- `Kubeflock: Check cluster target`
- `Kubeflock: Show cluster target`
- `Kubeflock: Create sandbox`
- `Kubeflock: List sandboxes`
- `Kubeflock: Reconnect sandbox`
- `Kubeflock: Disconnect sandbox`

The create action opens a popup that asks for the sandbox name, approved template, SSH identity file, and confirmation before it changes the cluster.

## Command reference

```text
kubeflock cluster config --context NAME --namespace NAME
kubeflock cluster config show [--output text|json]
kubeflock cluster check [--timeout 60s] [--output text|json]

kubeflock sandbox create NAME --template NAME --identity PATH [--timeout 5m]
kubeflock sandbox list [--output text|json]
kubeflock sandbox connect NAME --identity PATH
kubeflock sandbox reconnect [NAME]
kubeflock sandbox disconnect [NAME]

kubeflock version
kubeflock help
```

Every subcommand accepts these path overrides:

```text
--config PATH
--kubeconfig PATH
--kubectl PATH
--state-dir PATH
```

Kubeflock does not copy repository credentials, model credentials, workstation credentials, or SSH agents into a Sandbox. It does not expose a Sandbox or PVC deletion command.
