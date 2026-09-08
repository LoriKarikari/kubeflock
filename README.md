# Kubeflock

Kubeflock gives Herdr users agent work environments on Kubernetes.

This repo starts with issue 1. You pick an explicit context and namespace, then run a read-only check before anything else gets created.

## Install

You need Go 1.25 and kubectl.

```sh
go build -o kubeflock ./cmd/kubeflock
herdr plugin link /path/to/kubeflock
```

Herdr installs from GitHub run the build step from the manifest. For a local link, build by hand after you pull.

## Use

Pin the target. I use the homelab context and my own namespace here. Change both to match your cluster.

```sh
./kubeflock cluster config --context homelab --namespace kubeflock-check
./kubeflock cluster config show
./kubeflock cluster check
```

The check also runs from Herdr. Open the action palette and run Kubeflock check cluster target. It reads the same file at `~/.config/kubeflock/config.yaml`, so CLI and Herdr always look at the same cluster. Override with `--config PATH` or `KUBEFLOCK_CONFIG` when you need to.

JSON output works for scripts.

```sh
./kubeflock cluster check --output json
```

Exit code is 0 when every required check passes and 1 when a prerequisite fails. Advisory warnings do not fail the run. A missing LimitRange is one example. It shows as a warning because quotas already guard the namespace.

## What the check does

The check only reads. It runs `api-versions`, `api-resources`, `get`, and `auth can-i` through kubectl with your saved `--context` on every call. It never creates, patches, or deletes anything. Permission probes use `auth can-i`, which asks the API for a yes or no and keeps nothing.

It looks at:

* API reachability with the saved context
* Served Sandbox and Sandbox extension APIs
* RuntimeClass `gvisor` with a runsc handler
* StorageClasses and the default
* Namespace existence, ResourceQuotas, and LimitRanges
* RBAC for the later sandbox operations, like Sandbox and Claim create and delete, pod exec for SSH, and PVC and quota reads

Failures fall into groups so you know what to do next. Missing parts, denied RBAC, expired login, broken network, bad config, and timeouts each get their own message and fix. The output redacts tokens and auth codes. Complete OIDC login in a terminal instead of pasting codes into logs.

Every kubectl call carries `--request-timeout`, and `--timeout` bounds the whole run. Each call runs in its own process group. On timeout or cancel the runner terms the group, then kills it after a short grace. A credential helper that ignores TERM still dies on KILL, so nothing stays behind holding the OIDC cache lock.

## Tests

```sh
go test ./...
```

Tests use a fake kubectl script. They cover a saved context that differs from current-context, denied RBAC, a helper that ignores TERM, redaction, and a scan that proves the check only issues read verbs.
