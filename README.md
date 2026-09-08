# Kubeflock

Kubeflock is a Herdr plugin for checking whether a Kubernetes cluster is ready for agent work environments.

Choose a Kubernetes context and namespace, then check the prerequisites from the CLI or Herdr. Kubeflock currently configures and checks the target. It does not create sandboxes.

## Install

You need Linux or macOS, kubectl, and either Node 22.18 or newer in the 22.x series, or Node 24 or newer.

```sh
npm ci
npm run build
herdr plugin link /path/to/kubeflock
```

Installs from GitHub run the same build steps from the manifest. For a local link, build by hand after you pull.

## Use

Pin the target. Replace the example context and namespace with yours.

```sh
node dist/Cli.js cluster config --context homelab --namespace kubeflock-check
node dist/Cli.js cluster config show
node dist/Cli.js cluster check
```

After `npm link` the binary is also on your path as `kubeflock`.

In Herdr, open the action palette and run **Kubeflock: Check cluster target**.

The CLI and Herdr actions use the same config lookup. `--config PATH` takes precedence over `KUBEFLOCK_CONFIG`. Otherwise, Kubeflock reads `$XDG_CONFIG_HOME/kubeflock/config.yaml`, or `~/.config/kubeflock/config.yaml` when `XDG_CONFIG_HOME` is unset.

JSON output works for scripts.

```sh
node dist/Cli.js cluster check --output json
```

Exit codes are 0 when every required check passes, 1 for failed prerequisites or an overall timeout, and 2 for usage or config errors. Advisory warnings, such as a missing LimitRange, do not fail the run.

## What the check does

The check uses your saved context and namespace. It does not change persistent cluster resources.

It checks the following prerequisites:

- API reachability and the required Sandbox API versions.
- RuntimeClass `gvisor` with a runsc handler.
- StorageClasses and the default class.
- Namespace existence, ResourceQuota keys for compute and storage, and LimitRanges.
- Permissions needed for later sandbox operations.

Failures fall into groups so you know what to do next. Missing parts, denied RBAC, expired login, broken network, bad config, and timeouts each get their own message and fix. The output redacts tokens and auth codes. Complete OIDC login in a terminal instead of pasting codes into logs.

Use `--timeout` to limit the whole check and `--request-timeout` to limit individual Kubernetes requests.

```sh
node dist/Cli.js cluster check --timeout 60s --request-timeout 10s
```
