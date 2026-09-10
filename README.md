# Kubeflock

Kubeflock creates personal Kubernetes sandboxes and connects them to Herdr through the Kubernetes API. Sandboxes need no public SSH service or direct route from your workstation.

![Kubeflock creates a sandbox, launches Pi in Herdr, and reconnects without stopping Pi](docs/demo.gif)

## Requirements

- Go 1.27 or newer
- Herdr 0.9.0 or newer
- Helm 3
- A kubeconfig for a cluster with Agent Sandbox `v1beta1`, gVisor, and persistent storage

## Install

Build and push the starter sandbox image, or use a compatible image:

```bash
docker build --tag REGISTRY/kubeflock-sandbox:VERSION sandbox-image
docker push REGISTRY/kubeflock-sandbox:VERSION
```

Set `sandbox.image` in your values file to the image tag or digest. See [sandbox image documentation](sandbox-image/README.md) for contents and authentication.

Build the binary, install the CLI, and link the plugin:

```bash
go build -o bin/kubeflock ./cmd/kubeflock
go install ./cmd/kubeflock
herdr plugin link .
```

Copy the example values, edit for your cluster, and install the chart:

```bash
cp charts/kubeflock/values.example.yaml values.yaml
helm upgrade --install kubeflock charts/kubeflock \
  --namespace kubeflock-system \
  --create-namespace \
  --values values.yaml \
  --wait
```

The chart creates the developer namespace, access rules, budgets, sandbox template, and warm pool (standbys default to zero). See [Helm chart documentation](charts/kubeflock/README.md) for all values and GitOps use.

## Configure the target cluster

Save the target context and namespace:

```bash
kubeflock cluster config --context NAME --namespace NAME
```

The saved context persists across `kubectl` context switches.

Show the saved target:

```bash
kubeflock cluster config show [--output text|json]
```

Check cluster support:

```bash
kubeflock cluster check [--timeout 60s] [--output text|json]
```

## Manage sandboxes

### Create and connect

```bash
kubeflock sandbox create my-agent \
  --template dev-small \
  --identity ~/.ssh/id_ed25519 \
  --repository https://github.com/example/project.git \
  --branch main
```

Creates the sandbox, connects it to Herdr, and clones the repository into `/home/agent/project`. Omit `--repository` and `--branch` for an empty sandbox.

List approved credentials and attach what the sandbox needs:

```bash
kubeflock sandbox credential list
kubeflock sandbox create my-agent \
  --template dev-small \
  --identity ~/.ssh/id_ed25519 \
  --credential anthropic
```

Each alias maps to a Secret key in the configured namespace. Values transfer over stdin and export as the administrator-defined environment variable. They never enter images, local state, command arguments, or diagnostic output. No cross-namespace references.

Credentials persist in `~/.config/kubeflock/credentials` (mode `0600`) across stop, resume, and restore. Re-running `create` refreshes rotated credentials. A missing Secret stops credential attachment but leaves the sandbox available.

Retrying a failed create reuses saved Claim, Sandbox, PVC, and Herdr identities. A failed clone leaves the sandbox available for another attempt without replacing an existing checkout.

Configure Git credentials or SSH keys inside the sandbox. Repository URLs with embedded credentials are rejected. No keys, credentials, or agents are copied from your workstation.

### List sandboxes

```bash
kubeflock sandbox list [--output text|json]
```

Reports `provisioning`, `ready`, `failed`, and `disconnected` states.

### Connect

```bash
kubeflock sandbox connect NAME --identity PATH
```

The first connection saves the sandbox host key.

### Reconnect

```bash
kubeflock sandbox reconnect [NAME]
```

Refuses a changed host key.

### Disconnect

```bash
kubeflock sandbox disconnect [NAME]
```

The sandbox keeps running.

### Stop

```bash
kubeflock sandbox stop [NAME] [--timeout 5m]
```

Disconnects Herdr, stops compute, and keeps the persistent home.

### Resume

```bash
kubeflock sandbox resume [NAME] [--timeout 5m]
```

Starts a new Pod for the existing Sandbox and reconnects with the saved host key.

### Delete

```bash
kubeflock sandbox delete [NAME] [--timeout 5m]
```

Stops compute, orphan-deletes the Claim and Sandbox with UID checks, and records the PVC as a retained home.

## Manage retained homes

Deleting a sandbox retains its persistent home. List, restore, or permanently delete retained homes below.

### List retained homes

```bash
kubeflock sandbox home list [--output text|json]
```

Shows each home by PVC name and UID, with source sandbox, template, capacity, storage class, and state.

### Restore a retained home

Use the PVC UID from `kubeflock sandbox home list`:

```bash
kubeflock sandbox create my-agent \
  --home 330cc485-d9e2-4ddd-8144-fa893496188a \
  --template dev-small \
  --identity ~/.ssh/id_ed25519
```

Use the original sandbox name. Omitting `--home` when a retained home exists prints the PVC UID and refuses the create.

Restore uses the template recorded at deletion and prints the image for approval. It forces a cold Sandbox so the controller reattaches the original PVC. `--repository` is not accepted; clone inside the restored sandbox.

### Permanently delete a retained home

```bash
kubeflock sandbox home delete PVC_UID [--confirm PVC_UID] [--timeout 5m]
```

Shows target details and a data-loss warning. Interactive use requires entering the exact PVC UID; scripts pass it with `--confirm`.

The command refuses storage that is allocated, mounted, restoring, replaced, or ambiguously owned. It also refuses a `Retain` reclaim policy. For `Delete` policies, it deletes only the PVC (with a UID check) and succeeds after both PVC and persistent volume disappear.
