#!/usr/bin/env node
import { Effect } from "effect";
import { FileSystem } from "@effect/platform";
import { NodeFileSystem, NodeRuntime } from "@effect/platform-node";
import { runCheck, type CheckReport } from "./Check.js";
import { defaultPath, load, save, validate } from "./Config.js";
import { sanitizeLines } from "./Sanitize.js";
import { kubectlStderr, kubectlStdout, runKubectl } from "./Runner.js";

export const version = "0.1.0";

const usage = (): string => `kubeflock - Herdr agent environments on Kubernetes

Usage:
  kubeflock cluster config --context NAME --namespace NAME
  kubeflock cluster config show [--output text|json]
  kubeflock cluster check [--timeout 60s] [--output text|json]
  kubeflock version

Flags (each subcommand):
  --config PATH       config file (default $KUBEFLOCK_CONFIG or ~/.config/kubeflock/config.yaml)
  --kubeconfig PATH   kubeconfig file (default $KUBECONFIG or ~/.kube/config)
  --kubectl PATH      kubectl binary (default kubectl)

The saved context pins Kubeflock's target. Changing kubectl's current
context never retargets Kubeflock; every check passes --context explicitly.`;

export function flagValue(argv: ReadonlyArray<string>, name: string, fallback: string): string;
export function flagValue(argv: ReadonlyArray<string>, name: string): string | undefined;
export function flagValue(argv: ReadonlyArray<string>, name: string, fallback?: string): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === name) return argv[i + 1];
    if (a.startsWith(`${name}=`)) return a.slice(name.length + 1);
  }
  return fallback;
}

export const parseDuration = (raw: string): number => {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(raw.trim());
  if (!m) throw new Error(`bad duration "${raw}" (try 60s, 500ms, 2m)`);
  const n = Number(m[1]);
  switch (m[2] ?? "s") {
    case "ms":
      return n;
    case "s":
      return n * 1000;
    case "m":
      return n * 60 * 1000;
    case "h":
      return n * 3600 * 1000;
    default:
      throw new Error(`bad duration "${raw}"`);
  }
};

const defaultKubectl = (): string => process.env["KUBEFLOCK_KUBECTL"] ?? "kubectl";

const printTextReport = (rep: CheckReport): void => {
  console.log(`Kubeflock cluster check: context="${rep.context}" namespace="${rep.namespace}"`);
  let nOk = 0;
  for (const c of rep.checks) {
    const mark = c.ok ? "ok" : c.advisory ? "warn" : "FAIL";
    console.log(`  [${mark}] ${c.name}: ${c.message}`);
    if (!c.ok && c.remediation) console.log(`         fix: ${c.remediation}`);
    if (!c.ok && c.category) console.log(`         category: ${c.category}`);
    if (c.ok) nOk++;
  }
  console.log(
    rep.ok
      ? `PASS: ${nOk}/${rep.checks.length} checks passed`
      : `FAIL: ${nOk}/${rep.checks.length} checks passed; fix the FAIL rows and rerun`,
  );
};

const validateContext = (
  kubectlPath: string | undefined,
  kubeconfig: string | undefined,
  want: string,
): Effect.Effect<void, Error> =>
  Effect.gen(function*() {
    const out = yield* runKubectl(["config", "get-contexts", "-o", "name"], {
      kubectlPath,
      kubeconfig,
      timeoutMs: 15000,
    }).pipe(
      Effect.mapError((e): Error => {
        const raw = kubectlStderr(e) || kubectlStdout(e) || (e._tag === "KubectlSpawnError" ? e.cause : "kubectl failed");
        return new Error(`could not read kubeconfig contexts: ${sanitizeLines(raw).split("\n")[0]?.slice(0, 200)}`);
      }),
    );
    if (!out.split("\n").map((l) => l.trim()).includes(want)) {
      return yield* Effect.fail(new Error(`context "${want}" not found in kubeconfig; list with: kubectl config get-contexts`));
    }
  });

interface GlobalOpts {
  readonly configPath: string;
  readonly kubeconfig: string | undefined;
  readonly kubectlPath: string;
}

// main returns the process exit code instead of throwing: 0 pass, 1 failed
// prerequisites, 2 usage or config error. NodeRuntime.runMain preserves
// process.exitCode on success, and SIGINT/SIGTERM interrupt the Effect so
// scope finalizers kill leftover kubectl groups before exit.
const cmdConfig = (argv: ReadonlyArray<string>, g: GlobalOpts): Effect.Effect<number, never, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    if (argv[0] === "show") {
      const rest = argv.slice(1);
      const output = flagValue(rest, "--output", "text");
      const loaded = yield* load(g.configPath).pipe(
        Effect.match({ onFailure: (e) => ({ failed: e.cause }) as const, onSuccess: (c) => ({ cfg: c }) as const }),
      );
      if ("failed" in loaded) {
        console.error(`kubeflock: ${loaded.failed}`);
        return 2;
      }
      const c = loaded.cfg;
      if (output === "json") {
        console.log(JSON.stringify({ context: c.context, namespace: c.namespace, config: g.configPath }, null, 2));
      } else if (output === "text") {
        console.log(`context:   ${c.context}\nnamespace: ${c.namespace}\nconfig:    ${g.configPath}`);
      } else {
        console.error(`kubeflock: unknown --output "${output}"`);
        return 2;
      }
      return 0;
    }
    const contextName = flagValue(argv, "--context");
    const namespace = flagValue(argv, "--namespace");
    if (!contextName || !namespace) {
      console.error("kubeflock: --context and --namespace are required");
      return 2;
    }
    const cfg = { context: contextName, namespace };
    const bad = yield* validate(cfg).pipe(
      Effect.match({ onFailure: (e) => e.cause, onSuccess: () => null }),
    );
    if (bad) {
      console.error(`kubeflock: ${bad}`);
      return 2;
    }
    const ctxErr = yield* validateContext(g.kubectlPath, g.kubeconfig, contextName).pipe(
      Effect.match({ onFailure: (e) => e.message, onSuccess: () => null }),
    );
    if (ctxErr) {
      console.error(`kubeflock: ${ctxErr}`);
      return 2;
    }
    const saveErr = yield* save(g.configPath, cfg).pipe(
      Effect.match({ onFailure: (e) => e.cause, onSuccess: () => null }),
    );
    if (saveErr) {
      console.error(`kubeflock: ${saveErr}`);
      return 2;
    }
    console.log(`saved target context="${cfg.context}" namespace="${cfg.namespace}" to ${g.configPath}`);
    return 0;
  });

const cmdCheck = (argv: ReadonlyArray<string>, g: GlobalOpts): Effect.Effect<number, never, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const output = flagValue(argv, "--output", "text")!;
    let timeoutMs: number;
    let requestTimeoutSec: number;
    try {
      timeoutMs = parseDuration(flagValue(argv, "--timeout", "60s"));
      requestTimeoutSec = Math.max(parseDuration(flagValue(argv, "--request-timeout", "10s")) / 1000, 1);
    } catch (e) {
      console.error(`kubeflock: ${(e as Error).message}`);
      return 2;
    }
    if (output !== "text" && output !== "json") {
      console.error(`kubeflock: unknown --output "${output}"`);
      return 2;
    }
    const cfg = yield* load(g.configPath).pipe(
      Effect.match({ onFailure: (e) => ({ failed: e.cause }) as const, onSuccess: (c) => ({ cfg: c }) as const }),
    );
    if ("failed" in cfg) {
      console.error(`kubeflock: ${cfg.failed}`);
      return 2;
    }
    const rep = yield* runCheck(cfg.cfg, {
      kubectlPath: g.kubectlPath,
      kubeconfig: g.kubeconfig,
      requestTimeoutSec,
    }).pipe(
      Effect.timeoutFail({
        duration: timeoutMs,
        onTimeout: () => "overall-timeout" as const,
      }),
      Effect.catchAll(() => Effect.succeed("overall-timeout" as const)),
    );
    if (rep === "overall-timeout") {
      console.error("kubeflock: check timed out. Clear any stuck login helper, then rerun with a longer --timeout.");
      return 1;
    }
    if (output === "json") {
      console.log(JSON.stringify(rep, null, 2));
    } else {
      printTextReport(rep);
    }
    // Nonzero exit when prerequisites fail.
    return rep.ok ? 0 : 1;
  });

export const main = (argv: ReadonlyArray<string>): Effect.Effect<void, never, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    if (argv.length === 0 || argv.includes("--help") || argv[0] === "help" || argv[0] === "-h") {
      console.log(usage());
      process.exitCode = argv.length === 0 ? 2 : 0;
      return;
    }
    if (argv[0] === "version" || argv[0] === "--version" || argv[0] === "-V") {
      console.log(`kubeflock ${version}`);
      return;
    }
    if (argv[0] !== "cluster") {
      console.error(`kubeflock: unknown command "${argv[0]}"`);
      process.exitCode = 2;
      return;
    }
    const g: GlobalOpts = {
      configPath: flagValue(argv, "--config", defaultPath()),
      kubeconfig: flagValue(argv, "--kubeconfig") ?? process.env["KUBECONFIG"],
      kubectlPath: flagValue(argv, "--kubectl", defaultKubectl()),
    };
    const sub = argv[1];
    if (sub === "config") {
      process.exitCode = yield* cmdConfig(argv.slice(2), g);
      return;
    }
    if (sub === "check") {
      process.exitCode = yield* cmdCheck(argv.slice(2), g);
      return;
    }
    console.error(`kubeflock: unknown cluster subcommand "${sub}"`);
    process.exitCode = 2;
  });

const isMain = process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  NodeRuntime.runMain(Effect.provide(main(process.argv.slice(2)), NodeFileSystem.layer));
}
