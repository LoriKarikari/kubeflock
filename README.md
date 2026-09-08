# Kubeflock

Kubeflock gives Herdr users agent work environments on Kubernetes.

This repo starts with the cluster check. You pick an explicit context and namespace, then run a read-only check before anything else gets created.

## Install

You need Linux or macOS, Node 20 or newer, and kubectl.

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

The check runs `api-versions`, `api-resources`, `get`, and `auth can-i` through kubectl with your saved `--context` on every call. It does not change persistent cluster resources. Permission probes use transient SelfSubjectAccessReviews through `auth can-i`.

It checks the following prerequisites:

- API reachability and the required Sandbox API versions.
- RuntimeClass `gvisor` with a runsc handler.
- StorageClasses and the default class.
- Namespace existence, ResourceQuota keys for compute and storage, and LimitRanges.
- Permissions needed for later sandbox operations.

Failures fall into groups so you know what to do next. Missing parts, denied RBAC, expired login, broken network, bad config, and timeouts each get their own message and fix. The output redacts tokens and auth codes. Complete OIDC login in a terminal instead of pasting codes into logs.

`cluster check` passes `--request-timeout` to each kubectl call. A separate process deadline bounds stalled credential helpers, and `--timeout` bounds the whole check. Cleanup kills each call's process group, including helpers that ignore SIGTERM.

## Tests

```sh
npm test
```

`npm test` builds the CLI, then runs unit and subprocess tests with fake kubectl executables and temporary config files. Tests cover linked entry points, config validation, context pinning, API versions, quotas, RBAC, redaction, and process cleanup. They also check that probes use only permitted kubectl commands.

## Code map

- `src/Config.ts` loads, validates, and saves the target.
- `src/Runner.ts` runs kubectl with process deadlines and cleanup.
- `src/Classify.ts` groups failures and supplies remediation text.
- `src/Sanitize.ts` redacts credentials from diagnostics.
- `src/Check.ts` runs probes and builds the report.
- `src/Cli.ts` handles flags, output, and exit codes.
