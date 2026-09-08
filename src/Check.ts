import { Effect, Either, Option, Schema } from "effect";
import type { KubeTarget } from "./Config.js";
import { classify, remediation, type Category } from "./Classify.js";
import {
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
  readonly category?: Category;
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
  readonly subresource?: string;
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
  { verb: "create", resource: "pods", subresource: "exec", namespaced: true, advisory: false },
  { verb: "get", resource: "pods", subresource: "log", namespaced: true, advisory: false },
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
    if (t) return t;
  }
  return "unknown error";
};

const classifiedResult = (name: string, action: string, err: KubectlErr): CheckResult => {
  const stderr = kubectlStderr(err);
  const cat = classify(stderr, err._tag === "KubectlTimeoutError");
  const detail = firstUseful(stderr, kubectlStdout(err), err._tag === "KubectlSpawnError" ? err.cause : "kubectl failed");
  return fail(name, `could not ${action}: ${sanitizeLines(detail).slice(0, 500)}`, cat);
};

const parseJson = <A, I>(raw: string, schema: Schema.Schema<A, I>): A | null =>
  Option.getOrNull(Schema.decodeUnknownOption(Schema.parseJson(schema))(raw));

const permArgs = (cfg: KubeTarget, req: string, p: Perm): Array<string> => {
  const base = p.namespaced
    ? namespacedArgs(cfg, req, ["auth", "can-i", p.verb, p.resource])
    : baseArgs(cfg, req, ["auth", "can-i", p.verb, p.resource]);
  // TYPE/NAME selects an object, not a subresource.
  return p.subresource ? [...base, `--subresource=${p.subresource}`] : base;
};

const computeQuotaRe = /^(pods|cpu|memory|requests\.cpu|requests\.memory|limits\.cpu|limits\.memory|requests\.ephemeral-storage|limits\.ephemeral-storage)$/;
const storageQuotaRe = /^(persistentvolumeclaims|requests\.storage)$/;

const resourceMetadata = Schema.Struct({
  name: Schema.optional(Schema.String),
  annotations: Schema.optional(Schema.Record({ key: Schema.String, value: Schema.String })),
});
const runtimeClass = Schema.Struct({ handler: Schema.optional(Schema.String) });
const storageClasses = Schema.Struct({
  items: Schema.optional(Schema.Array(Schema.Struct({ metadata: Schema.optional(resourceMetadata) }))),
});
const resourceQuotas = Schema.Struct({
  items: Schema.optional(Schema.Array(Schema.Struct({
    metadata: Schema.optional(resourceMetadata),
    spec: Schema.optional(Schema.Struct({
      hard: Schema.optional(Schema.Record({ key: Schema.String, value: Schema.String })),
    })),
  }))),
});
const limitRanges = Schema.Struct({ items: Schema.optional(Schema.Array(Schema.Struct({}))) });

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

  const attempt = (
    name: string,
    action: string,
    args: ReadonlyArray<string>,
  ): Effect.Effect<{ out: string; err: CheckResult | null }> =>
    Effect.match(run(args), {
      onFailure: (err) => ({ out: kubectlStdout(err), err: classifiedResult(name, action, err) }),
      onSuccess: (out) => ({ out, err: null }),
    });

  return Effect.gen(function*() {
    const checks: Array<CheckResult> = [];

    const connectivity = yield* attempt("api-connectivity", "reach the Kubernetes API with the saved context", baseArgs(cfg, req, ["api-versions"]));
    const served: Set<string> | null = connectivity.err
      ? null
      : new Set(connectivity.out.split("\n").map((l) => l.trim()).filter((l) => l.length > 0));
    checks.push(connectivity.err ?? ok("api-connectivity", "API reachable with saved context"));

    for (const group of [
      {
        name: "agents-api",
        apiGroup: "agents.x-k8s.io",
        version: "v1beta1",
        want: ["sandboxes"],
        display: "Sandbox API agents.x-k8s.io/v1beta1",
      },
      {
        name: "extensions-api",
        apiGroup: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        want: ["sandboxclaims", "sandboxtemplates", "sandboxwarmpools"],
        display: "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1",
      },
    ]) {
      if (served !== null && !served.has(`${group.apiGroup}/${group.version}`)) {
        checks.push(fail(group.name, `${group.display} is not served`, "missing-infrastructure"));
        continue;
      }
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
      const parsed = parseJson(rc.out, runtimeClass);
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
      const parsed = parseJson(sc.out, storageClasses);
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
      const parsed = parseJson(quota.out, resourceQuotas);
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
        const items = parsed.items ?? [];
        const names = items.map((i) => i.metadata?.name ?? "?").join(", ");
        const keys = [...new Set(items.flatMap((i) => Object.keys(i.spec?.hard ?? {})))];
        const hasCompute = keys.some((k) => computeQuotaRe.test(k));
        const hasStorage = keys.some((k) => storageQuotaRe.test(k));
        if (!hasCompute || !hasStorage) {
          const missing = [!hasCompute ? "compute (pods, cpu, memory)" : null, !hasStorage ? "storage" : null]
            .filter((s) => s !== null)
            .join(" and ");
          checks.push(
            fail(
              "budgets-quota",
              `ResourceQuota ${names} sets no ${missing} budget (hard: ${keys.join(", ") || "empty"})`,
              "missing-infrastructure",
            ),
          );
        } else {
          checks.push(ok("budgets-quota", `ResourceQuota present: ${names}`));
        }
      }
    }

    const limits = yield* attempt("budgets-limits", "read LimitRanges in target namespace", namespacedArgs(cfg, req, ["get", "limitrange", "-o", "json"]));
    if (limits.err) {
      checks.push({ ...limits.err, advisory: true });
    } else {
      const parsed = parseJson(limits.out, limitRanges);
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
        const shown = p.subresource ? `${p.resource}/${p.subresource}` : p.resource;
        const name = `perm-${p.verb}-${shortResource(shown)}`;
        const probed = yield* Effect.either(run(permArgs(cfg, req, p)));
        const out = Either.isLeft(probed) ? kubectlStdout(probed.left) : probed.right;
        // kubectl prints "no" and exits 1 for denied access.
        const answer = out.trim().toLowerCase();
        if (answer === "yes") return ok(name, `can ${p.verb} ${shown}`);
        if (answer === "no" || answer.startsWith("no ")) {
          const scope = p.namespaced ? "namespace" : "cluster scope";
          const denied = fail(name, `cannot ${p.verb} ${shown} in ${scope}`, "denied");
          return p.advisory ? { ...denied, advisory: true } : denied;
        }
        if (Either.isLeft(probed)) {
          const r = classifiedResult(name, `check permission ${p.verb} ${shown}`, probed.left);
          return p.advisory ? { ...r, advisory: true } : r;
        }
        const odd = fail(name, `unexpected permission answer for ${p.verb} ${shown}: "${sanitizeLines(out)}"`, "unknown");
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
