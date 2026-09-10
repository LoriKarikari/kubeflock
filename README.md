# Kubeflock

Kubeflock creates personal Kubernetes sandboxes and connects them to Herdr through the Kubernetes API. A sandbox needs neither a public SSH service nor a direct route from your workstation.

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

Set `sandbox.image` in your values file to the image tag or digest. The [sandbox image documentation](sandbox-image/README.md) describes its contents and authentication model.

Build the binary that Herdr runs, install the CLI, and link the plugin:

```bash
go build -o bin/kubeflock ./cmd/kubeflock
go install ./cmd/kubeflock
herdr plugin link .
```

Copy the example values file, edit it for your cluster, and install the chart:

```bash
cp charts/kubeflock/values.example.yaml values.yaml
helm upgrade --install kubeflock charts/kubeflock \
  --namespace kubeflock-system \
  --create-namespace \
  --values values.yaml \
  --wait
```

The chart creates the developer namespace, access rules, budgets, sandbox template, and warm pool. Standbys default to zero. The [Helm chart documentation](charts/kubeflock/README.md) covers all values, controller installation, and GitOps use.

## Configure the target cluster

Save the Kubernetes context and namespace that Kubeflock must use:

```bash
kubeflock cluster config --context NAME --namespace NAME
```

Kubeflock keeps using the saved context if your current `kubectl` context changes.

Show the saved target:

```bash
kubeflock cluster config show [--output text|json]
```

Check that the target supports Kubeflock:

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

Kubeflock creates the sandbox, connects it to Herdr, and clones the repository into `/home/agent/project`. Omit `--repository` and `--branch` to create an empty sandbox.

List administrator-approved credentials and attach only the ones this sandbox needs:

```bash
kubeflock sandbox credential list
kubeflock sandbox create my-agent \
  --template dev-small \
  --identity ~/.ssh/id_ed25519 \
  --credential anthropic
```

Each alias maps to one Secret key in the configured namespace. Kubeflock verifies that the caller can read that Secret, transfers its value to the sandbox over standard input, and exports it under the administrator-defined environment variable for interactive shells. Values do not enter images, local state, command arguments, or diagnostic output. Cross-namespace references are not supported.

Credential files use mode `0600` under `~/.config/kubeflock/credentials`. The shell setup and files persist in the sandbox home across stop, resume, deletion with home retention, and restore. Delete or rotate them inside the sandbox when that persistence is not wanted. A retained home records the aliases it was attached with, and restore re-attaches the same selection. Repeating the same `create` command against an existing sandbox copies the current Secret values and refreshes rotated credentials. An inaccessible or missing Secret stops credential attachment but leaves the sandbox and its files available for retry.

If creation fails and you retry it, Kubeflock reuses the saved Claim, Sandbox, PVC, and Herdr identities. If the clone fails, the sandbox remains available for login and another attempt. Kubeflock does not replace an existing checkout.

Configure Git credentials or SSH keys inside the sandbox, or select an administrator-approved environment credential. Kubeflock rejects repository URLs that contain credentials. It does not copy private keys, Git or model credentials, or SSH agents from your workstation.

### List sandboxes

```bash
kubeflock sandbox list [--output text|json]
```

The command reports `provisioning`, `ready`, `failed`, and `disconnected` states.

### Connect

```bash
kubeflock sandbox connect NAME --identity PATH
```

The first connection requires an identity file and saves the sandbox host key.

### Reconnect

```bash
kubeflock sandbox reconnect [NAME]
```

Reconnect accepts no flags. Kubeflock refuses a changed host key.

### Disconnect

```bash
kubeflock sandbox disconnect [NAME]
```

The sandbox and its remote processes keep running.

### Stop

```bash
kubeflock sandbox stop [NAME] [--timeout 5m]
```

Kubeflock disconnects Herdr, stops the compute, and keeps the persistent home.

### Resume

```bash
kubeflock sandbox resume [NAME] [--timeout 5m]
```

Kubeflock starts a new Pod for the existing Sandbox and reconnects with the saved host key.

### Delete

```bash
kubeflock sandbox delete [NAME] [--timeout 5m]
```

Kubeflock stops the compute and orphan-deletes the Claim and Sandbox with UID checks. It keeps the PVC and records it as a retained home.

## Manage retained homes

Deleting a sandbox retains its persistent home. You can list, restore, or permanently delete that home.

### List retained homes

```bash
kubeflock sandbox home list [--output text|json]
```

The command shows each home by PVC name and UID. It also shows the source sandbox, template, capacity, storage class, and state. The list includes only the configured Kubernetes context and namespace.

A home has the `restoring` state when an interrupted restore left its record behind. Retry the restore to finish attaching it. A home in the `deleting` state also shows the persistent volume identity when Kubeflock recorded one.

### Restore a retained home

Use the PVC UID from `kubeflock sandbox home list`:

```bash
kubeflock sandbox create my-agent \
  --home 330cc485-d9e2-4ddd-8144-fa893496188a \
  --template dev-small \
  --identity ~/.ssh/id_ed25519
```

Use the original sandbox name. Agent Sandbox derives the PVC name from it. If you run `create` with that name but omit `--home`, Kubeflock refuses the retained data and prints the PVC UID to use.

Kubeflock uses the template recorded when you deleted the sandbox. Before it attaches the home, it prints the template image for approval. Restore forces a cold Sandbox with the original resource name so the controller reattaches the retained PVC instead of handing out a different standby home. Restore does not accept `--repository`. Clone the repository inside the restored sandbox instead.

### Permanently delete a retained home

```bash
kubeflock sandbox home delete PVC_UID [--confirm PVC_UID] [--timeout 5m]
```

Kubeflock shows the target, PVC identity, capacity, storage class, persistent volume, and a data-loss warning. Interactive use requires you to enter the exact PVC UID. Scripts must pass the same UID with `--confirm`. A missing or different UID stops the command without deleting data.

The command refuses storage that is allocated, mounted, restoring, replaced, or owned ambiguously. It also refuses a `Retain` reclaim policy because Kubernetes cannot confirm deletion of the storage itself.

For a `Delete` reclaim policy, Kubeflock records the PVC and persistent volume identities. It deletes only that PVC, with a UID check, and succeeds after both objects disappear. If the persistent volume is already gone, Kubeflock can still clear the record. If the PVC is already gone, Kubeflock refuses the operation because it cannot identify replacement storage. A failed attempt remains in the `deleting` state so you can retry it safely.
