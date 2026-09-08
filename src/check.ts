import { Effect, Either, Option, Schema } from "effect";
import type { KubeTarget } from "./config.js";
import { classify, remediation, type Category } from "./classify.js";
import {
  kubectlStderr,
  kubectlStdout,
  runKubectl,
  type KubectlError as KubectlErr,
} from "./runner.js";
import { sanitizeLines } from "./sanitize.js";

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

interface Probe {
  readonly out: string;
  readonly err: CheckResult | null;
}

type Attempt = (name: string, action: string, args: ReadonlyArray<string>) => Effect.Effect<Probe>;
type Run = (args: ReadonlyArray<string>) => Effect.Effect<string, KubectlErr>;

const checkApis = (cfg: KubeTarget, req: string, attempt: Attempt): Effect.Effect<ReadonlyArray<CheckResult>> =>
  Effect.gen(function*() {
    const checks: Array<CheckResult> = [];
    const connectivity = yield* attempt("api-connectivity", "reach the Kubernetes API with the saved context", baseArgs(cfg, req, ["api-versions"]));
    const served = connectivity.err
      ? null
      : new Set(connectivity.out.split("\n").map((line) => line.trim()).filter(Boolean));
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
      const result = yield* attempt(
        group.name,
        `discover ${group.display}`,
        baseArgs(cfg, req, ["api-resources", `--api-group=${group.apiGroup}`, "-o", "name"]),
      );
      if (result.err) {
        checks.push(result.err);
        continue;
      }
      const missing = group.want.filter((resource) => !result.out.toLowerCase().includes(resource));
      checks.push(missing.length > 0
        ? fail(group.name, `${group.display} served but missing: ${missing.join(", ")}`, "missing-infrastructure")
        : ok(group.name, `${group.display} served`));
    }
    return checks;
  });

const checkRuntimeClass = (cfg: KubeTarget, req: string, attempt: Attempt): Effect.Effect<CheckResult> =>
  Effect.gen(function*() {
    const result = yield* attempt("runtimeclass-gvisor", "read RuntimeClass gvisor", baseArgs(cfg, req, ["get", "runtimeclass", "gvisor", "-o", "json"]));
    if (result.err) return result.err;
    const parsed = parseJson(result.out, runtimeClass);
    if (parsed === null) return fail("runtimeclass-gvisor", "RuntimeClass gvisor returned unreadable JSON", "unknown");
    const handler = parsed.handler ?? "";
    return handler.toLowerCase().includes("runsc")
      ? ok("runtimeclass-gvisor", `RuntimeClass gvisor present (handler ${handler})`)
      : fail("runtimeclass-gvisor", `RuntimeClass gvisor handler is "${handler}", want runsc`, "missing-infrastructure");
  });

const checkStorage = (cfg: KubeTarget, req: string, attempt: Attempt): Effect.Effect<CheckResult> =>
  Effect.gen(function*() {
    const result = yield* attempt("storage", "list StorageClasses", baseArgs(cfg, req, ["get", "storageclass", "-o", "json"]));
    if (result.err) return result.err;
    const parsed = parseJson(result.out, storageClasses);
    if (parsed === null) return fail("storage", "StorageClass list returned unreadable JSON", "unknown");
    const items = parsed.items ?? [];
    if (items.length === 0) return fail("storage", "no StorageClasses available for sandbox homes", "missing-infrastructure");
    const names = items.map((item) => item.metadata?.name ?? "?");
    const defaultName = items.find((item) => item.metadata?.annotations?.["storageclass.kubernetes.io/is-default-class"] === "true")
      ?.metadata?.name;
    const defaultLabel = defaultName ? ` (default ${defaultName})` : "";
    return ok("storage", `${names.length} StorageClass(es): ${names.join(", ")}${defaultLabel}`);
  });

const checkQuota = (cfg: KubeTarget, req: string, attempt: Attempt): Effect.Effect<CheckResult> =>
  Effect.gen(function*() {
    const result = yield* attempt("budgets-quota", "read ResourceQuotas in target namespace", namespacedArgs(cfg, req, ["get", "resourcequota", "-o", "json"]));
    if (result.err) return result.err;
    const parsed = parseJson(result.out, resourceQuotas);
    if (parsed === null) return fail("budgets-quota", "ResourceQuota list returned unreadable JSON", "unknown");
    const items = parsed.items ?? [];
    if (items.length === 0) {
      return fail(
        "budgets-quota",
        "no ResourceQuota in target namespace; set explicit compute/storage budgets via the Helm chart",
        "missing-infrastructure",
      );
    }
    const names = items.map((item) => item.metadata?.name ?? "?").join(", ");
    const keys = [...new Set(items.flatMap((item) => Object.keys(item.spec?.hard ?? {})))];
    const hasCompute = keys.some((key) => computeQuotaRe.test(key));
    const hasStorage = keys.some((key) => storageQuotaRe.test(key));
    if (hasCompute && hasStorage) return ok("budgets-quota", `ResourceQuota present: ${names}`);
    const missing = [!hasCompute ? "compute (pods, cpu, memory)" : null, !hasStorage ? "storage" : null]
      .filter((name) => name !== null)
      .join(" and ");
    return fail(
      "budgets-quota",
      `ResourceQuota ${names} sets no ${missing} budget (hard: ${keys.join(", ") || "empty"})`,
      "missing-infrastructure",
    );
  });

const checkLimits = (cfg: KubeTarget, req: string, attempt: Attempt): Effect.Effect<CheckResult> =>
  Effect.gen(function*() {
    const result = yield* attempt("budgets-limits", "read LimitRanges in target namespace", namespacedArgs(cfg, req, ["get", "limitrange", "-o", "json"]));
    if (result.err) return { ...result.err, advisory: true };
    const parsed = parseJson(result.out, limitRanges);
    if (parsed === null) return { ...fail("budgets-limits", "LimitRange list returned unreadable JSON", "unknown"), advisory: true };
    const count = (parsed.items ?? []).length;
    return count === 0
      ? { ...fail("budgets-limits", "no LimitRange in target namespace", "missing-infrastructure"), advisory: true }
      : ok("budgets-limits", `${count} LimitRange(s) present`);
  });

const checkPermissions = (cfg: KubeTarget, req: string, run: Run): Effect.Effect<ReadonlyArray<CheckResult>> =>
  Effect.forEach(requiredPerms, (permission) => Effect.gen(function*() {
    const shown = permission.subresource ? `${permission.resource}/${permission.subresource}` : permission.resource;
    const name = `perm-${permission.verb}-${shortResource(shown)}`;
    const probed = yield* Effect.either(run(permArgs(cfg, req, permission)));
    const out = Either.isLeft(probed) ? kubectlStdout(probed.left) : probed.right;
    const answer = out.trim().toLowerCase();
    if (answer === "yes") return ok(name, `can ${permission.verb} ${shown}`);
    if (answer === "no" || answer.startsWith("no ")) {
      const scope = permission.namespaced ? "namespace" : "cluster scope";
      const denied = fail(name, `cannot ${permission.verb} ${shown} in ${scope}`, "denied");
      return permission.advisory ? { ...denied, advisory: true } : denied;
    }
    if (Either.isLeft(probed)) {
      const result = classifiedResult(name, `check permission ${permission.verb} ${shown}`, probed.left);
      return permission.advisory ? { ...result, advisory: true } : result;
    }
    const unexpected = fail(name, `unexpected permission answer for ${permission.verb} ${shown}: "${sanitizeLines(out)}"`, "unknown");
    return permission.advisory ? { ...unexpected, advisory: true } : unexpected;
  }), { concurrency: 6 });

export const runCheck = (cfg: KubeTarget, opts: CheckOptions): Effect.Effect<CheckReport, never> => {
  const req = `${opts.requestTimeoutSec ?? 10}s`;
  const perCallMs = Math.max((opts.requestTimeoutSec ?? 10) * 1000 + 5000, 15000);
  const run: Run = (args) => runKubectl(args, {
    kubectlPath: opts.kubectlPath,
    kubeconfig: opts.kubeconfig,
    extraEnv: opts.extraEnv,
    timeoutMs: perCallMs,
  });
  const attempt: Attempt = (name, action, args) => Effect.match(run(args), {
    onFailure: (error) => ({ out: kubectlStdout(error), err: classifiedResult(name, action, error) }),
    onSuccess: (out) => ({ out, err: null }),
  });

  return Effect.gen(function*() {
    const api = yield* checkApis(cfg, req, attempt);
    const runtime = yield* checkRuntimeClass(cfg, req, attempt);
    const storage = yield* checkStorage(cfg, req, attempt);
    const namespace = yield* attempt("namespace", `read namespace "${cfg.namespace}"`, baseArgs(cfg, req, ["get", "namespace", cfg.namespace, "-o", "json"]));
    const quota = yield* checkQuota(cfg, req, attempt);
    const limits = yield* checkLimits(cfg, req, attempt);
    const permissions = yield* checkPermissions(cfg, req, run);
    const checks = [
      ...api,
      runtime,
      storage,
      namespace.err ?? ok("namespace", `namespace "${cfg.namespace}" exists`),
      quota,
      limits,
      ...permissions,
    ];
    return {
      context: cfg.context,
      namespace: cfg.namespace,
      ok: checks.every((check) => check.ok || check.advisory),
      checks,
      checkedAt: (opts.now?.() ?? new Date()).toISOString(),
    } satisfies CheckReport;
  });
};
