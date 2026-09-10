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

## Usage

### Cluster

```bash
kubeflock cluster config --context NAME --namespace NAME
kubeflock cluster config show [--output text|json]
kubeflock cluster check       [--timeout 60s] [--output text|json]
```

The saved context persists across `kubectl` context switches.

### Create

```bash
kubeflock sandbox create NAME --template NAME --identity PATH [flags]
```

| Flag | Description |
|------|-------------|
| `--repository URL` | Clone into `/home/agent/project` |
| `--branch NAME` | Branch to clone (requires `--repository`) |
| `--credential ALIAS` | Attach an approved credential (repeatable) |
| `--home PVC_UID` | Restore a retained home |
| `--timeout DURATION` | Default `5m` |

### List

```bash
kubeflock sandbox list [--output text|json]
```

### Connect

```bash
kubeflock sandbox connect NAME --identity PATH
```

### Reconnect

```bash
kubeflock sandbox reconnect [NAME]
```

Refuses a changed host key.

### Disconnect

```bash
kubeflock sandbox disconnect [NAME]
```

### Stop

```bash
kubeflock sandbox stop [NAME] [--timeout 5m]
```

Keeps the persistent home.

### Resume

```bash
kubeflock sandbox resume [NAME] [--timeout 5m]
```

Starts a new Pod and reconnects with the saved host key.

### Delete

```bash
kubeflock sandbox delete [NAME] [--timeout 5m]
```

Retains the PVC as a home you can restore or permanently delete.

### Credentials

```bash
kubeflock sandbox credential list
```

Each alias maps to a Secret key in the configured namespace. Values transfer over stdin and never enter images, local state, or command arguments. Re-running `create` refreshes rotated credentials.

Repository URLs with embedded credentials are rejected. No keys, credentials, or agents are copied from your workstation.

### Retained homes

```bash
kubeflock sandbox home list   [--output text|json]
kubeflock sandbox home delete PVC_UID [--confirm PVC_UID] [--timeout 5m]
```

Restore a home by passing `--home PVC_UID` to `sandbox create` with the original sandbox name. Restore uses the template recorded at deletion and prints the image for approval.

`home delete` shows a data-loss warning and requires the exact PVC UID for confirmation (`--confirm` for scripts). It refuses storage that is allocated, mounted, or ambiguously owned.
