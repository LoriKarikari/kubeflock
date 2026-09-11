# Kubeflock

A Herdr plugin that provisions Agent Sandbox environments on Kubernetes and connects them through the Kubernetes API.

![Kubeflock creates a sandbox, launches Pi in Herdr, and reconnects without stopping Pi](docs/demo.gif)

## Requirements

- Go 1.27 or newer
- Herdr 0.9.0 or newer
- Helm 3
- A Kubernetes cluster with Agent Sandbox `v1beta1`, gVisor, and persistent storage

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

The saved context sticks even if you switch `kubectl` contexts.

### Create

```bash
kubeflock sandbox create NAME --template NAME --identity PATH [flags]
```

| Flag | Description |
|------|-------------|
| `--timeout DURATION` | Default `5m` |

### List

```bash
kubeflock sandbox list [--output text|json]
```

Shows all sandboxes and their current state.

### Connect

```bash
kubeflock sandbox connect NAME --identity PATH
```

Saves the sandbox host key on first use.

### Reconnect

```bash
kubeflock sandbox reconnect [NAME]
```

Reuses the saved identity and host key.

### Disconnect

```bash
kubeflock sandbox disconnect [NAME]
```

Detaches Herdr but leaves the sandbox running.

### Stop

```bash
kubeflock sandbox stop [NAME] [--timeout 5m]
```

Stops compute but keeps the persistent home.

### Resume

```bash
kubeflock sandbox resume [NAME] [--timeout 5m]
```

Spins up a new Pod with the existing home and reconnects.

### Delete

```bash
kubeflock sandbox delete NAME [--confirm DELETE] [--timeout 5m]
```

Permanently deletes the sandbox and its workspace storage. Interactive use requires typing `DELETE`; scripts can pass `--confirm DELETE`.
