# Kubeflock Helm chart

This chart prepares one developer namespace for Kubeflock. It creates the namespace labels, access rules, budgets, starter template, zero-replica warm pool, SSH public-key configuration, and ingress policy.

The chart does not install gVisor, a StorageClass, or the Agent Sandbox controller. It does not adopt an existing controller or change active Sandboxes.

## Prepare values

Copy the example and replace every placeholder:

```bash
cp charts/kubeflock/values.example.yaml values.yaml
```

`namespace.name` is the developer namespace managed by the chart. The Helm release itself lives separately in `kubeflock-system`.

## Sandbox image

The chart does not publish or bundle a Sandbox image. Build the starter image from [`sandbox-image/`](../../sandbox-image/) or supply a compatible custom image. Push the image to a registry that the cluster can pull from, then set `sandbox.image` to its tag or digest.

Compatible images must contain the remote Herdr server at version 0.9.0 or newer, OpenSSH configured through `SSH_PORT`, `socat`, and a user with UID/GID 1000. `sandbox.sshPort` defaults to 2222.

The Herdr application installed on the workstation is separate from the remote Herdr server in the Sandbox image. The private SSH key also remains on the workstation. Only its public key belongs in values.

Capacity is explicit. `maxActiveSandboxes` determines namespace Pod, CPU, and memory quotas. `maxRetainedHomes` determines PVC and storage quotas. A retained home consumes storage after its Sandbox stops using compute.

## Agent Sandbox controller

Reuse an existing compatible controller when its `v1beta1` core and extension APIs are already served:

```bash
kubectl api-resources --api-group=agents.x-k8s.io
kubectl api-resources --api-group=extensions.agents.x-k8s.io
```

To install the controller, inspect and apply a pinned upstream release. The combined manifest enables the Claim, Template, and WarmPool extensions required by Kubeflock:

```bash
VERSION=v1.0.1
curl -fL -o agent-sandbox.yaml \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${VERSION}/sandbox-with-extensions.yaml"
kubectl diff -f agent-sandbox.yaml
kubectl apply -f agent-sandbox.yaml
```

Running `kubectl apply` is the explicit approval step. Kubeflock does not run it automatically. Node-level gVisor installation remains the cluster administrator's responsibility.

## Inspect rendered resources

Helm validates the values before rendering:

```bash
helm lint charts/kubeflock -f values.yaml
helm template kubeflock charts/kubeflock \
  --namespace kubeflock-system \
  --values values.yaml > kubeflock.yaml
```

Review `kubeflock.yaml` before applying it directly or committing it to Flux or Argo CD.

## Install

```bash
helm upgrade --install kubeflock charts/kubeflock \
  --namespace kubeflock-system \
  --create-namespace \
  --values values.yaml \
  --wait
```

The installer needs permission to create a Namespace, ClusterRole, ClusterRoleBinding, and namespaced resources. A denied operation stops the Helm release. It does not broaden the installer's permissions.

Configure Kubeflock after installation:

```bash
kubeflock cluster config --context my-context --namespace developer-sandboxes
kubeflock cluster check
```

## Access model

`access.subjects` accepts Kubernetes `User`, `Group`, and `ServiceAccount` subjects. The chart grants sandbox lifecycle access only in the developer namespace. Cluster-wide access is read-only and limited to the namespace, StorageClass, and `gvisor` RuntimeClass checks.

Every subject shares one trust domain. The role grants `pods/exec` create and PersistentVolumeClaim patch in the namespace, so any subject can read and write every Sandbox, the home mounted into it, and any retained home recorded from it. Use one namespace per user, or per group that may already read each other's files. Per-user isolation needs a namespace per user, because `pods/exec` alone defeats separation inside one namespace. The chart refuses the broad `system:authenticated`, `system:unauthenticated`, and `system:serviceaccounts` groups for the same reason.

The Sandbox Pod receives no automatic service-account token. The chart does not create a service account for Sandboxes or place private keys, repository credentials, or model credentials in the cluster.

## Upgrade behavior

A chart upgrade updates chart-owned policy, budgets, templates, and unclaimed warm-pool configuration. Agent Sandbox applies template changes to new Sandboxes. Existing Sandboxes and their PVCs are not chart resources, so Helm does not restart or delete them.

The Agent Sandbox controller remains independently managed. Upgrading this chart does not upgrade or replace it.
