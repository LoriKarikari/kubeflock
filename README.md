# Kubeflock

Kubeflock creates personal Kubernetes sandboxes and connects them to Herdr. Connections travel through the Kubernetes API, so Sandboxes need no public SSH service or direct workstation route.

## Requirements

- Go 1.26 or newer
- Herdr 0.9.0 or newer
- Helm 3
- A kubeconfig for a cluster with Agent Sandbox `v1beta1`, gVisor, and persistent storage

## Install

Build and push the starter Sandbox image, or use a compatible custom image:

```bash
docker build --tag REGISTRY/kubeflock-sandbox:VERSION sandbox-image
docker push REGISTRY/kubeflock-sandbox:VERSION
```

Set `sandbox.image` in your values file to that tag or digest. See [`sandbox-image/README.md`](sandbox-image/README.md) for the image contents and authentication model.

```bash
go build -o bin/kubeflock ./cmd/kubeflock
go install ./cmd/kubeflock
herdr plugin link .
```

Prepare a values file and install the cluster resources:

```bash
cp charts/kubeflock/values.example.yaml values.yaml
helm upgrade --install kubeflock charts/kubeflock \
  --namespace kubeflock-system \
  --create-namespace \
  --values values.yaml \
  --wait
```

The chart creates the developer namespace, access rules, budgets, Sandbox template, and zero-replica warm pool. See [`charts/kubeflock/README.md`](charts/kubeflock/README.md) for values, controller installation, and GitOps use.

## Configure

```bash
kubeflock cluster config --context NAME --namespace NAME
kubeflock cluster config show
kubeflock cluster check
```

The saved context remains authoritative when the current kubectl context changes.

## Sandboxes

Create and connect a Sandbox:

```bash
kubeflock sandbox create my-agent \
  --template dev-small \
  --identity ~/.ssh/id_ed25519
```

Manage Sandboxes:

```bash
kubeflock sandbox list [--output text|json]
kubeflock sandbox connect NAME --identity PATH
kubeflock sandbox reconnect [NAME]
kubeflock sandbox disconnect [NAME]
```

Creation retries reuse the saved Claim, Sandbox, PVC, and Herdr identities. Disconnecting leaves the Sandbox and its remote processes running.

Kubeflock reports `provisioning`, `ready`, `failed`, and `disconnected` lifecycle states. Herdr provides matching actions for cluster checks, target display, creation, listing, reconnection, and disconnection.

## Options

```text
kubeflock cluster config show [--output text|json]
kubeflock cluster check [--timeout 60s] [--output text|json]
kubeflock sandbox create NAME --template NAME --identity PATH [--timeout 5m]

--config PATH
--kubeconfig PATH
--kubectl PATH
--state-dir PATH
```

Kubeflock does not copy private keys, repository credentials, model credentials, or SSH agents into a Sandbox. It provides no Sandbox or PVC deletion command.
