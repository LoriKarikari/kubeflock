import { FileSystem } from "@effect/platform";
import { Effect } from "effect";
import { createHash } from "node:crypto";
import * as Path from "node:path";
import type { KubeTarget } from "./config.js";
import { connect, type ConnectOptions } from "./connection.js";
import { defaultStateDir, listConnections } from "./connection-state.js";
import { listMachines } from "./herdr.js";
import {
  createSandboxClaim,
  getSandboxClaim,
  listSandboxClaims,
  resolveApprovedTemplate,
  resolvePersistentHome,
  resolveSandbox,
  type SandboxClaim,
} from "./kubernetes.js";
import {
  listManagedSandboxes,
  saveManagedSandbox,
  type BoundSandbox,
  type ManagedSandbox,
} from "./sandbox-state.js";

const managedBy = "app.kubernetes.io/managed-by";
const kubernetesName = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/;
const failedReason = /error|fail|invalid|forbidden|quota|unschedulable|conflict|not.?found|multiple/i;

interface ClaimPending {
  readonly state: "provisioning";
  readonly step: "readiness";
  readonly message: string;
}

interface ClaimReady {
  readonly state: "ready";
  readonly sandboxName: string;
}

interface ClaimFailed {
  readonly state: "failed";
  readonly step: "readiness";
  readonly message: string;
}

type ClaimProgress = ClaimPending | ClaimReady | ClaimFailed;

export const claimProgress = (claim: SandboxClaim): ClaimProgress => {
  const conditions = claim.status?.conditions ?? [];
  const ready = conditions.find((condition) => condition.type === "Ready");
  const detail = [ready?.reason, ready?.message].filter(Boolean).join(": ") || "waiting for the Sandbox controller";
  if (ready?.status === "True" && claim.status?.sandbox?.name) {
    return { state: "ready", sandboxName: claim.status.sandbox.name };
  }
  if (ready?.status === "False" && failedReason.test(detail)) {
    return { state: "failed", step: "readiness", message: detail };
  }
  return { state: "provisioning", step: "readiness", message: detail };
};

export interface CreateSandboxOptions extends ConnectOptions {
  readonly template: string;
  readonly timeoutMs?: number;
  readonly pollMs?: number;
}

export interface CreatedSandbox {
  readonly name: string;
  readonly claimUid: string;
  readonly sandboxUid: string;
  readonly template: string;
  readonly warmPool: string;
  readonly home: BoundSandbox["home"];
  readonly sshAlias: string;
}

const selectManaged = (
  target: KubeTarget,
  name: string,
  stateDir: string,
): Effect.Effect<ManagedSandbox | undefined, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const matches = (yield* listManagedSandboxes(stateDir)).map(({ sandbox }) => sandbox).filter((sandbox) =>
      sandbox.claim.context === target.context
      && sandbox.claim.namespace === target.namespace
      && sandbox.claim.name === name,
    );
    if (matches.length > 1) return yield* Effect.fail(new Error(`multiple saved sandboxes match ${target.namespace}/${name}`));
    return matches[0];
  });

const verifyClaim = (
  claim: SandboxClaim,
  target: KubeTarget,
  name: string,
  warmPool: string,
  saved?: ManagedSandbox,
): void => {
  if (claim.metadata.labels?.[managedBy] !== "kubeflock") {
    throw new Error(`SandboxClaim ${target.namespace}/${name} is not managed by Kubeflock`);
  }
  if (claim.spec.warmPoolRef.name !== warmPool) {
    throw new Error(`SandboxClaim ${target.namespace}/${name} uses warm pool ${claim.spec.warmPoolRef.name}, not ${warmPool}`);
  }
  if (saved && claim.metadata.uid !== saved.claim.uid) {
    throw new Error(`SandboxClaim ${target.namespace}/${name} was replaced: expected UID ${saved.claim.uid}, found ${claim.metadata.uid}`);
  }
};

const obtainClaim = (
  target: KubeTarget,
  name: string,
  warmPool: string,
  kubeconfig: string | undefined,
): Effect.Effect<SandboxClaim, Error> =>
  Effect.gen(function*() {
    const current = yield* getSandboxClaim(target, name, kubeconfig);
    if (current) return current;
    return yield* createSandboxClaim(target, name, warmPool, kubeconfig).pipe(
      Effect.catchAll((createError) => getSandboxClaim(target, name, kubeconfig).pipe(
        Effect.flatMap((concurrent) => concurrent ? Effect.succeed(concurrent) : Effect.fail(createError)),
      )),
    );
  });

const waitForReady = (
  target: KubeTarget,
  initial: SandboxClaim,
  timeoutMs: number,
  pollMs: number,
  kubeconfig: string | undefined,
): Effect.Effect<ClaimReady, Error> =>
  Effect.gen(function*() {
    const deadline = Date.now() + timeoutMs;
    let claim = initial;
    while (true) {
      const progress = claimProgress(claim);
      if (progress.state === "ready") return progress;
      if (progress.state === "failed") return yield* Effect.fail(new Error(`sandbox failed during ${progress.step}: ${progress.message}`));
      const remaining = deadline - Date.now();
      if (remaining <= 0) return yield* Effect.fail(new Error(`sandbox provisioning timed out during ${progress.step}: ${progress.message}`));
      yield* Effect.sleep(Math.min(pollMs, remaining));
      const current = yield* getSandboxClaim(target, claim.metadata.name, kubeconfig);
      if (!current) return yield* Effect.fail(new Error(`SandboxClaim ${target.namespace}/${claim.metadata.name} disappeared during provisioning`));
      if (current.metadata.uid !== claim.metadata.uid) {
        return yield* Effect.fail(new Error(`SandboxClaim ${target.namespace}/${claim.metadata.name} was replaced during provisioning`));
      }
      claim = current;
    }
  });

const createUnlocked = (
  target: KubeTarget,
  name: string,
  options: CreateSandboxOptions,
): Effect.Effect<CreatedSandbox, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    if (!kubernetesName.test(name) || name.length > 63) return yield* Effect.fail(new Error(`invalid sandbox name "${name}"`));
    if (!kubernetesName.test(options.template) || options.template.length > 63) return yield* Effect.fail(new Error(`invalid template name "${options.template}"`));
    if (!options.identityFile) return yield* Effect.fail(new Error("specify --identity for sandbox creation"));
    const fs = yield* FileSystem.FileSystem;
    const identityFile = yield* fs.realPath(Path.resolve(options.identityFile));
    yield* fs.access(identityFile);
    const stateDir = options.stateDir ?? defaultStateDir();
    const approved = yield* resolveApprovedTemplate(target, options.template, options.kubeconfig);
    const saved = yield* selectManaged(target, name, stateDir);
    if (saved && (saved.template !== approved.name || saved.warmPool !== approved.warmPool)) {
      return yield* Effect.fail(new Error(`saved sandbox ${target.namespace}/${name} uses a different template or warm pool`));
    }
    if (saved && saved.identityFile !== identityFile) {
      return yield* Effect.fail(new Error(`saved sandbox ${target.namespace}/${name} uses a different SSH identity file`));
    }

    const claim = yield* obtainClaim(target, name, approved.warmPool, options.kubeconfig);
    yield* Effect.try({
      try: () => verifyClaim(claim, target, name, approved.warmPool, saved),
      catch: (error) => error instanceof Error ? error : new Error("SandboxClaim validation failed"),
    });
    const claimed: ManagedSandbox = saved ?? {
      version: 1,
      phase: "claimed",
      claim: { context: target.context, namespace: target.namespace, name, uid: claim.metadata.uid },
      template: approved.name,
      warmPool: approved.warmPool,
      identityFile,
    };
    if (!saved) yield* saveManagedSandbox(stateDir, claimed);

    const ready = yield* waitForReady(
      target,
      claim,
      options.timeoutMs ?? 300_000,
      options.pollMs ?? 2_000,
      options.kubeconfig,
    );
    const resolved = yield* resolveSandbox(
      target,
      ready.sandboxName,
      options.kubeconfig,
      claimed.phase === "bound" ? claimed.sandbox.uid : undefined,
    );
    if (ready.sandboxName !== name) {
      return yield* Effect.fail(new Error(`SandboxClaim ${target.namespace}/${name} was bound to unexpected Sandbox ${ready.sandboxName}`));
    }
    const home = yield* resolvePersistentHome(target, resolved.identity, approved.homeTemplate, options.kubeconfig);
    let bound: BoundSandbox;
    if (claimed.phase === "bound") {
      if (claimed.home.uid !== home.uid) return yield* Effect.fail(new Error(`sandbox home ${home.name} was replaced`));
      bound = claimed;
    } else {
      bound = { ...claimed, phase: "bound", sandbox: resolved.identity, home };
      yield* saveManagedSandbox(stateDir, bound);
    }
    const connection = yield* connect(target, {
      ...options,
      name,
      expectedUid: bound.sandbox.uid,
      identityFile,
      stateDir,
    });
    return {
      name,
      claimUid: bound.claim.uid,
      sandboxUid: bound.sandbox.uid,
      template: bound.template,
      warmPool: bound.warmPool,
      home: bound.home,
      sshAlias: connection.ssh.alias,
    };
  });

export const createManagedSandbox = (
  target: KubeTarget,
  name: string,
  options: CreateSandboxOptions,
): Effect.Effect<CreatedSandbox, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const stateDir = options.stateDir ?? defaultStateDir();
    const locks = Path.join(stateDir, "locks");
    const key = createHash("sha256").update(`${target.context}\0${target.namespace}\0${name}`).digest("hex");
    const lock = Path.join(locks, key);
    yield* fs.makeDirectory(locks, { recursive: true, mode: 0o700 });
    return yield* Effect.acquireUseRelease(
      fs.writeFileString(lock, `${process.pid}\n`, { flag: "wx", mode: 0o600 }).pipe(
        Effect.mapError(() => new Error(`sandbox ${target.namespace}/${name} is already being created`)),
      ),
      () => createUnlocked(target, name, options),
      () => fs.remove(lock, { force: true }).pipe(Effect.orDie),
    );
  });

export type SandboxLifecycleState = "provisioning" | "ready" | "failed" | "disconnected";

export interface SandboxStatus {
  readonly name: string;
  readonly namespace: string;
  readonly state: SandboxLifecycleState;
  readonly step?: "claim" | "readiness" | "connection";
  readonly message?: string;
  readonly claimUid: string;
  readonly sandboxUid?: string;
  readonly template: string;
  readonly warmPool: string;
  readonly home?: BoundSandbox["home"];
}

export const listManagedSandboxStatus = (
  target: KubeTarget,
  stateDir: string,
  kubeconfig?: string,
): Effect.Effect<ReadonlyArray<SandboxStatus>, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const managed = (yield* listManagedSandboxes(stateDir)).map(({ sandbox }) => sandbox).filter((sandbox) =>
      sandbox.claim.context === target.context && sandbox.claim.namespace === target.namespace,
    );
    const [claims, connections, machines] = yield* Effect.all([
      listSandboxClaims(target, kubeconfig),
      listConnections(stateDir),
      listMachines(),
    ]);
    return managed.map((saved): SandboxStatus => {
      const base = {
        name: saved.claim.name,
        namespace: saved.claim.namespace,
        claimUid: saved.claim.uid,
        sandboxUid: saved.phase === "bound" ? saved.sandbox.uid : undefined,
        template: saved.template,
        warmPool: saved.warmPool,
        home: saved.phase === "bound" ? saved.home : undefined,
      };
      const claim = claims.find((candidate) => candidate.metadata.uid === saved.claim.uid);
      if (!claim) return { ...base, state: "failed", step: "claim", message: "saved SandboxClaim is missing" };
      const progress = claimProgress(claim);
      if (progress.state !== "ready") return { ...base, ...progress };
      if (saved.phase !== "bound") return { ...base, state: "provisioning", step: "connection", message: "waiting to record Sandbox and home identities" };
      const connection = connections.find((candidate) => candidate.connection.sandbox.uid === saved.sandbox.uid)?.connection;
      if (!connection) return { ...base, state: "provisioning", step: "connection", message: "waiting for native Herdr registration" };
      if (connection.phase === "prepared") return { ...base, state: "failed", step: "connection", message: "native Herdr registration did not complete" };
      const machine = machines.find((candidate) => candidate.id === connection.profileId);
      if (!machine) return { ...base, state: "failed", step: "connection", message: "saved Herdr machine is missing" };
      return { ...base, state: machine.enabled ? "ready" : "disconnected" };
    });
  });
