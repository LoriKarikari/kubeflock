# Kubeflock

Kubeflock gives Herdr users agent work environments on Kubernetes.

This repo starts with the cluster check. You pick an explicit context and namespace, then run a read-only check before anything else gets created.

## Install

You need Node 20 or newer and kubectl.

```sh
npm ci
npm run build
herdr plugin link /path/to/kubeflock
```

Installs from GitHub run the same build steps from the manifest. For a local link, build by hand after you pull.

## Use

Pin the target. I use the homelab context and my own namespace here. Change both to match your cluster.

```sh
node dist/Cli.js cluster config --context homelab --namespace kubeflock-check
node dist/Cli.js cluster config show
node dist/Cli.js cluster check
```

After `npm link` the binary is also on your path as `kubeflock`.

The check also runs from Herdr. Open the action palette and run Kubeflock check cluster target. It reads the same file at `~/.config/kubeflock/config.yaml`, so CLI and Herdr always look at the same cluster. Override with `--config PATH` or `KUBEFLOCK_CONFIG` when you need to.

JSON output works for scripts.

```sh
node dist/Cli.js cluster check --output json
```

Exit code is 0 when every required check passes and 1 when a prerequisite fails. Usage errors exit 2. Advisory warnings do not fail the run. A missing LimitRange is one example. It shows as a warning because quotas already guard the namespace.

## What the check does

The check only reads. It runs `api-versions`, `api-resources`, `get`, and `auth can-i` through kubectl with your saved `--context` on every call. It never creates, patches, or deletes anything. Permission probes use `auth can-i`, which asks the API for a yes or no and keeps nothing.

It looks at API reachability with the saved context, the served Sandbox and Sandbox extension APIs, RuntimeClass `gvisor` with a runsc handler, StorageClasses and the default, namespace existence with ResourceQuotas and LimitRanges, and the RBAC the later sandbox operations need.

Failures fall into groups so you know what to do next. Missing parts, denied RBAC, expired login, broken network, bad config, and timeouts each get their own message and fix. The output redacts tokens and auth codes. Complete OIDC login in a terminal instead of pasting codes into logs.

Every kubectl call carries `--request-timeout`, and `--timeout` bounds the whole run. Each call runs in its own process group as an Effect scope. Timeout or interrupt terms the group and the scope release kills whatever remains. A credential helper that ignores TERM still dies in the release, so nothing stays behind holding the OIDC cache lock.

## Tests

```sh
npm test
```

Tests use a fake kubectl script. They cover a saved context that differs from current-context, denied RBAC, a helper that ignores TERM, interruption cleanup, redaction, and a scan that proves the check only issues read verbs.

## Code map

`Config.ts` owns the saved target and its validation. `Runner.ts` owns bounded subprocess runs. `Classify.ts` and `Sanitize.ts` own failure groups and redaction. `Check.ts` owns the probes and the report. `Cli.ts` owns flags, output, and exit codes.
