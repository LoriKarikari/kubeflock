// The read-only cluster prerequisite check. Every Kubernetes interaction
// goes through kubectl with an explicit --context and --request-timeout and
// uses only read verbs (api-versions, api-resources, get, auth can-i). The
// check never creates, patches, or deletes cluster state; permission probing
// uses the ephemeral SelfSubjectAccessReview behind `kubectl auth can-i`.

import { Effect } from "effect";
import type { KubeTarget } from "./Config.js";
import { classify, remediation, type Category } from "./Classify.js";
import {
  isKubectlError,
  isTimeout,
  kubectlStderr,
  kubectlStdout,
  runKubectl,
  type KubectlError as KubectlErr,
} from "./Runner.js";
import { sanitizeLines } from "./Sanitize.js";

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly advisory?: boolean;
  readonly category?: string;
  readonly message: string;
  readonly remediation?: string;
}

export interface CheckReport {
  readonly context: string;
  readonly namespace: string;
  readonly ok: boolean;
  readonly checks: ReadonlyArray<CheckResult>;
  readonly checkedAt: string;
}

export interface CheckOptions {
  readonly kubectlPath?: string;
  readonly kubeconfig?: string;
  readonly extraEnv?: NodeJS.ProcessEnv;
  readonly requestTimeoutSec?: number;
  readonly now?: () => Date;
}

interface Perm {
  readonly verb: string;
  readonly resource: string;
  readonly namespaced: boolean;
  readonly advisory: boolean;
}

const requiredPerms: ReadonlyArray<Perm> = [
  { verb: "get", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "list", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "watch", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "create", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "patch", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "delete", resource: "sandboxes.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "get", resource: "sandboxclaims.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "list", resource: "sandboxclaims.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "create", resource: "sandboxclaims.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "patch", resource: "sandboxclaims.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "delete", resource: "sandboxclaims.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "get", resource: "sandboxtemplates.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "list", resource: "sandboxtemplates.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "get", resource: "sandboxwarmpools.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "list", resource: "sandboxwarmpools.extensions.agents.x-k8s.io", namespaced: true, advisory: false },
  { verb: "get", resource: "pods", namespaced: true, advisory: false },
  { verb: "list", resource: "pods", namespaced: true, advisory: false },
  { verb: "create", resource: "pods/exec", namespaced: true, advisory: false },
  { verb: "get", resource: "pods/log", namespaced: true, advisory: false },
  { verb: "get", resource: "persistentvolumeclaims", namespaced: true, advisory: false },
  { verb: "list", resource: "persistentvolumeclaims", namespaced: true, advisory: false },
  { verb: "get", resource: "resourcequotas", namespaced: true, advisory: false },
  { verb: "list", resource: "resourcequotas", namespaced: true, advisory: false },
  { verb: "get", resource: "limitranges", namespaced: true, advisory: false },
  { verb: "get", resource: "secrets", namespaced: true, advisory: true },
  { verb: "get", resource: "storageclasses.storage.k8s.io", namespaced: false, advisory: false },
  { verb: "list", resource: "storageclasses.storage.k8s.io", namespaced: false, advisory: false },
  { verb: "get", resource: "runtimeclasses.node.k8s.io", namespaced: false, advisory: false },
  { verb: "get", resource: "namespaces", namespaced: false, advisory: false },
];

const ok = (name: string, message: string): CheckResult => ({ name, ok: true, message });

const fail = (name: string, message: string, cat: Category): CheckResult => ({
  name,
  ok: false,
  message,
  category: cat,
  remediation: remediation(cat),
});

const baseArgs = (cfg: KubeTarget, req: string, args: ReadonlyArray<string>): Array<string> => [
  "--context",
  cfg.context,
  "--request-timeout",
  req,
  ...args,
];

const namespacedArgs = (cfg: KubeTarget, req: string, args: ReadonlyArray<string>): Array<string> => [
  "--context",
  cfg.context,
  "-n",
  cfg.namespace,
  "--request-timeout",
  req,
  ...args,
];

const firstUseful = (...parts: Array<string>): string => {
  for (const p of parts) {
    const t = p.trim();
    if (t) return t.length > 500 ? t.slice(0, 500) : t;
  }
  return "unknown error";
};

const classifiedResult = (name: string, action: string, stdout: string, err: unknown): CheckResult => {
  const timedOut = isTimeout(err);
  const stderr = isKubectlError(err) ? kubectlStderr(err) : "";
  const cat = classify(stderr, timedOut);
  const detail = isKubectlError(err)
    ? firstUseful(stderr, kubectlStdout(err), err._tag === "KubectlSpawnError" ? err.cause : "kubectl failed")
    : firstUseful(stdout, (err as Error)?.message ?? String(err));
  return fail(name, `could not ${action}: ${sanitizeLines(detail)}`, cat);
};

const parseJson = <T>(raw: string): T | null => {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
};

const shortResource = (r: string): string =>
  r
    .replaceAll(".agents.x-k8s.io", "")
    .replaceAll(".extensions", "")
    .replaceAll(".storage.k8s.io", "")
    .replaceAll(".node.k8s.io", "")
    .replaceAll("/", "-");

export const runCheck = (cfg: KubeTarget, opts: CheckOptions): Effect.Effect<CheckReport, never> => {
  const req = `${opts.requestTimeoutSec ?? 10}s`;
  const perCallMs = Math.max((opts.requestTimeoutSec ?? 10) * 1000 + 5000, 15000);
  const run = (args: ReadonlyArray<string>): Effect.Effect<string, KubectlErr> =>
    runKubectl(args, {
      kubectlPath: opts.kubectlPath,
      kubeconfig: opts.kubeconfig,
      extraEnv: opts.extraEnv,
      timeoutMs: perCallMs,
    });

  // Each probe catches its own failure into a CheckResult, so the whole
  // check never fails as an Effect. Layered timeouts still apply: a stuck
  // probe reports itself instead of hanging the run.
  const attempt = (
    name: string,
    action: string,
    args: ReadonlyArray<string>,
  ): Effect.Effect<{ out: string; err: CheckResult | null }> =>
    Effect.matchEffect(run(args), {
      onFailure: (err) =>
        Effect.succeed({
          out: isKubectlError(err) ? kubectlStdout(err) : "",
          err: classifiedResult(name, action, isKubectlError(err) ? kubectlStdout(err) : "", err),
        }),
      onSuccess: (out) => Effect.succeed({ out, err: null }),
    });

  return Effect.gen(function*() {
    const checks: Array<CheckResult> = [];

    const connectivity = yield* attempt("api-connectivity", "reach the Kubernetes API with the saved context", baseArgs(cfg, req, ["api-versions"]));
    checks.push(connectivity.err ?? ok("api-connectivity", "API reachable with saved context"));

    for (const group of [
      {
        name: "agents-api",
        apiGroup: "agents.x-k8s.io",
        want: ["sandboxes"],
        display: "Sandbox API agents.x-k8s.io/v1beta1",
      },
      {
        name: "extensions-api",
        apiGroup: "extensions.agents.x-k8s.io",
        want: ["sandboxclaims", "sandboxtemplates", "sandboxwarmpools"],
        display: "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1",
      },
    ]) {
      const r = yield* attempt(
        group.name,
        `discover ${group.display}`,
        baseArgs(cfg, req, ["api-resources", `--api-group=${group.apiGroup}`, "-o", "name"]),
      );
      if (r.err) {
        checks.push(r.err);
        continue;
      }
      const low = r.out.toLowerCase();
      const missing = group.want.filter((w) => !low.includes(w));
      checks.push(
        missing.length > 0
          ? fail(group.name, `${group.display} served but missing: ${missing.join(", ")}`, "missing-infrastructure")
          : ok(group.name, `${group.display} served`),
      );
    }

    const rc = yield* attempt("runtimeclass-gvisor", "read RuntimeClass gvisor", baseArgs(cfg, req, ["get", "runtimeclass", "gvisor", "-o", "json"]));
    if (rc.err) {
      checks.push(rc.err);
    } else {
      const parsed = parseJson<{ handler?: unknown }>(rc.out);
      if (parsed === null) {
        checks.push(fail("runtimeclass-gvisor", "RuntimeClass gvisor returned unreadable JSON", "unknown"));
      } else if (!String(parsed.handler ?? "").toLowerCase().includes("runsc")) {
        checks.push(
          fail("runtimeclass-gvisor", `RuntimeClass gvisor handler is "${String(parsed.handler ?? "")}", want runsc`, "missing-infrastructure"),
        );
      } else {
        checks.push(ok("runtimeclass-gvisor", `RuntimeClass gvisor present (handler ${String(parsed.handler)})`));
      }
    }

    const sc = yield* attempt("storage", "list StorageClasses", baseArgs(cfg, req, ["get", "storageclass", "-o", "json"]));
    if (sc.err) {
      checks.push(sc.err);
    } else {
      const parsed = parseJson<{
        items?: Array<{ metadata?: { name?: string; annotations?: Record<string, string> } }>;
      }>(sc.out);
      if (parsed === null) {
        checks.push(fail("storage", "StorageClass list returned unreadable JSON", "unknown"));
      } else {
        const items = parsed.items ?? [];
        if (items.length === 0) {
          checks.push(fail("storage", "no StorageClasses available for sandbox homes", "missing-infrastructure"));
        } else {
          const names = items.map((i) => i.metadata?.name ?? "?");
          const def = items.find((i) => i.metadata?.annotations?.["storageclass.kubernetes.io/is-default-class"] === "true")
            ?.metadata?.name;
          checks.push(ok("storage", `${names.length} StorageClass(es): ${names.join(", ")}${def ? ` (default ${def})` : ""}`));
        }
      }
    }

    const ns = yield* attempt("namespace", `read namespace "${cfg.namespace}"`, baseArgs(cfg, req, ["get", "namespace", cfg.namespace, "-o", "json"]));
    checks.push(ns.err ?? ok("namespace", `namespace "${cfg.namespace}" exists`));

    const quota = yield* attempt("budgets-quota", "read ResourceQuotas in target namespace", namespacedArgs(cfg, req, ["get", "resourcequota", "-o", "json"]));
    if (quota.err) {
      checks.push(quota.err);
    } else {
      const parsed = parseJson<{ items?: Array<{ metadata?: { name?: string } }> }>(quota.out);
      if (parsed === null) {
        checks.push(fail("budgets-quota", "ResourceQuota list returned unreadable JSON", "unknown"));
      } else if ((parsed.items ?? []).length === 0) {
        checks.push(
          fail(
            "budgets-quota",
            "no ResourceQuota in target namespace; set explicit compute/storage budgets via the Helm chart",
            "missing-infrastructure",
          ),
        );
      } else {
        checks.push(ok("budgets-quota", `ResourceQuota present: ${(parsed.items ?? []).map((i) => i.metadata?.name ?? "?").join(", ")}`));
      }
    }

    const limits = yield* attempt("budgets-limits", "read LimitRanges in target namespace", namespacedArgs(cfg, req, ["get", "limitrange", "-o", "json"]));
    if (limits.err) {
      checks.push({ ...limits.err, advisory: true });
    } else {
      const parsed = parseJson<{ items?: Array<unknown> }>(limits.out);
      if (parsed === null) {
        checks.push({ ...fail("budgets-limits", "LimitRange list returned unreadable JSON", "unknown"), advisory: true });
      } else if ((parsed.items ?? []).length === 0) {
        checks.push({ ...fail("budgets-limits", "no LimitRange in target namespace", "missing-infrastructure"), advisory: true });
      } else {
        checks.push(ok("budgets-limits", `${(parsed.items ?? []).length} LimitRange(s) present`));
      }
    }

    const permResults = yield* Effect.forEach(requiredPerms, (p) =>
      Effect.gen(function*() {
        const args = p.namespaced
          ? namespacedArgs(cfg, req, ["auth", "can-i", p.verb, p.resource])
          : baseArgs(cfg, req, ["auth", "can-i", p.verb, p.resource]);
        const name = `perm-${p.verb}-${shortResource(p.resource)}`;
        const r = yield* attempt(name, `check permission ${p.verb} ${p.resource}`, args);
        if (r.err) return p.advisory ? { ...r.err, advisory: true } : r.err;
        const answer = r.out.trim().toLowerCase();
        if (answer.includes("yes")) return ok(name, `can ${p.verb} ${p.resource}`);
        if (answer.includes("no")) {
          const scope = p.namespaced ? "namespace" : "cluster scope";
          const denied = fail(name, `cannot ${p.verb} ${p.resource} in ${scope}`, "denied");
          return p.advisory ? { ...denied, advisory: true } : denied;
        }
        const odd = fail(name, `unexpected permission answer for ${p.verb} ${p.resource}: "${sanitizeLines(r.out)}"`, "unknown");
        return p.advisory ? { ...odd, advisory: true } : odd;
      }), { concurrency: 6 });
    checks.push(...permResults);

    return {
      context: cfg.context,
      namespace: cfg.namespace,
      ok: checks.every((c) => c.ok || c.advisory),
      checks,
      checkedAt: (opts.now?.() ?? new Date()).toISOString(),
    } satisfies CheckReport;
  });
};
