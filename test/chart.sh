#!/bin/sh
set -eu

chart="$(CDPATH= cd -- "$(dirname -- "$0")/../charts/kubeflock" && pwd)"
values="$chart/values.example.yaml"
rendered="$(mktemp)"
errors="$(mktemp)"
trap 'rm -f "$rendered" "$errors"' EXIT

helm lint "$chart" --values "$values"
helm template kubeflock "$chart" --namespace developer --values "$values" > "$rendered"

for kind in Namespace NetworkPolicy ResourceQuota LimitRange ClusterRole ClusterRoleBinding Role RoleBinding SandboxTemplate SandboxWarmPool; do
  grep -q "^kind: $kind$" "$rendered"
done

for value in \
  'pod-security.kubernetes.io/enforce: restricted' \
  'helm.sh/resource-policy: keep' \
  'runtimeClassName: gvisor' \
  'automountServiceAccountToken: false' \
  'allowPrivilegeEscalation: false' \
  'requests.storage: "40Gi"' \
  'replicas: 0'; do
  grep -q "$value" "$rendered"
done

for kind in CustomResourceDefinition Deployment Sandbox SandboxClaim PersistentVolumeClaim; do
  ! grep -q "^kind: $kind$" "$rendered"
done

if helm template kubeflock "$chart" --namespace developer > /dev/null 2> "$errors"; then
  echo "chart accepted missing required values" >&2
  exit 1
fi
grep -q 'access.subjects' "$errors"
grep -q 'sandbox.image' "$errors"
grep -q 'sandbox.sshPublicKey' "$errors"
grep -q 'sandbox.storage.className' "$errors"

if helm template kubeflock "$chart" --namespace developer --values "$values" \
  --set capacity.maxRetainedHomes=1 > /dev/null 2> "$errors"; then
  echo "chart accepted insufficient retained-home capacity" >&2
  exit 1
fi
grep -q 'maxRetainedHomes cannot be less than maxActiveSandboxes' "$errors"
