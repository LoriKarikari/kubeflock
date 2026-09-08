import { CoreV1Api, CustomObjectsApi, KubeConfig } from "@kubernetes/client-node";
import { Effect, Schema } from "effect";
import type { KubeTarget } from "./config.js";
import type { SandboxIdentity } from "./connection-state.js";
import { kubectlStderr, kubectlStdout, runCredentialHelper } from "./runner.js";

const sandboxSchema = Schema.Struct({
  metadata: Schema.Struct({
    name: Schema.String,
    namespace: Schema.String,
    uid: Schema.String,
  }),
  status: Schema.Struct({
    selector: Schema.String,
    conditions: Schema.Array(Schema.Struct({ type: Schema.String, status: Schema.String })),
  }),
});

const execSchema = Schema.Struct({
  command: Schema.String,
  args: Schema.optional(Schema.Array(Schema.String)),
  env: Schema.optional(Schema.NullOr(Schema.Array(Schema.Struct({ name: Schema.String, value: Schema.String })))),
});

const credentialSchema = Schema.Struct({
  status: Schema.Struct({
    token: Schema.optional(Schema.String),
    clientCertificateData: Schema.optional(Schema.String),
    clientKeyData: Schema.optional(Schema.String),
  }),
});

const podListSchema = Schema.Struct({
  items: Schema.Array(Schema.Struct({
    metadata: Schema.Struct({
      name: Schema.String,
      ownerReferences: Schema.Array(Schema.Struct({
        uid: Schema.String,
        controller: Schema.optional(Schema.Boolean),
      })),
      annotations: Schema.optional(Schema.Record({ key: Schema.String, value: Schema.String })),
    }),
    spec: Schema.Struct({ containers: Schema.Array(Schema.Struct({ name: Schema.String })) }),
  })),
});

export interface ResolvedSandbox {
  readonly identity: SandboxIdentity;
  readonly pod: string;
  readonly container: string;
}

const config = (context: string, kubeconfig?: string): Effect.Effect<KubeConfig, Error> =>
  Effect.gen(function*() {
    const kc = yield* Effect.try({
      try: () => {
        const loaded = new KubeConfig();
        if (kubeconfig) loaded.loadFromFile(kubeconfig);
        else loaded.loadFromDefault();
        if (!loaded.getContexts().some((candidate) => candidate.name === context)) {
          throw new Error(`context "${context}" not found in kubeconfig`);
        }
        loaded.setCurrentContext(context);
        return loaded;
      },
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const user = kc.getCurrentUser();
    if (!user?.exec) return kc;
    const exec = yield* Schema.decodeUnknown(execSchema)(user.exec).pipe(
      Effect.mapError(() => new Error("kubeconfig contains an invalid exec credential helper")),
    );
    const result = yield* runCredentialHelper(exec.command, exec.args ?? [], {
      extraEnv: Object.fromEntries(exec.env?.map(({ name, value }) => [name, value]) ?? []),
      timeoutMs: 60_000,
    }).pipe(
      Effect.mapError((error) => new Error(
        kubectlStderr(error) || kubectlStdout(error) || "kubeconfig credential helper failed",
      )),
    );
    const credential = yield* Schema.decodeUnknown(Schema.parseJson(credentialSchema))(result).pipe(
      Effect.mapError(() => new Error("kubeconfig credential helper returned an invalid ExecCredential")),
    );
    const status = credential.status;
    if (!status.token && !(status.clientCertificateData && status.clientKeyData)) {
      return yield* Effect.fail(new Error("kubeconfig credential helper returned no usable credentials"));
    }
    kc.users = kc.users.map((candidate) => candidate.name === user.name ? {
      ...candidate,
      exec: undefined,
      token: status.token,
      certData: status.clientCertificateData,
      keyData: status.clientKeyData,
    } : candidate);
    return kc;
  });

export const resolveSandbox = (
  target: KubeTarget,
  name: string,
  kubeconfig?: string,
  expectedUid?: string,
): Effect.Effect<ResolvedSandbox, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const custom = kc.makeApiClient(CustomObjectsApi);
    const core = kc.makeApiClient(CoreV1Api);
    const rawSandbox: unknown = yield* Effect.tryPromise({
      try: () => custom.getNamespacedCustomObject({
        group: "agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxes",
        name,
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const sandbox = yield* Schema.decodeUnknown(sandboxSchema)(rawSandbox);
    if (expectedUid && sandbox.metadata.uid !== expectedUid) {
      return yield* Effect.fail(new Error(
        `sandbox ${target.namespace}/${name} was replaced: expected UID ${expectedUid}, found ${sandbox.metadata.uid}`,
      ));
    }
    if (!sandbox.status.conditions.some((condition) => condition.type === "Ready" && condition.status === "True")) {
      return yield* Effect.fail(new Error(`sandbox ${target.namespace}/${name} is not ready`));
    }
    const rawPods: unknown = yield* Effect.tryPromise({
      try: () => core.listNamespacedPod({
        namespace: target.namespace,
        labelSelector: sandbox.status.selector,
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const pods = (yield* Schema.decodeUnknown(podListSchema)(rawPods)).items.filter((pod) =>
      pod.metadata.ownerReferences.some((owner) => owner.controller === true && owner.uid === sandbox.metadata.uid),
    );
    if (pods.length !== 1) {
      return yield* Effect.fail(new Error(
        `sandbox ${target.namespace}/${name} owns ${pods.length} matching pods; expected exactly one`,
      ));
    }
    const pod = pods[0]!;
    const preferred = pod.metadata.annotations?.["kubectl.kubernetes.io/default-container"];
    const container = preferred ?? (pod.spec.containers.length === 1 ? pod.spec.containers[0]!.name : undefined);
    if (!container || !pod.spec.containers.some((candidate) => candidate.name === container)) {
      return yield* Effect.fail(new Error(`pod ${target.namespace}/${pod.metadata.name} has no unambiguous default container`));
    }
    return {
      identity: {
        context: target.context,
        namespace: sandbox.metadata.namespace,
        name: sandbox.metadata.name,
        uid: sandbox.metadata.uid,
      },
      pod: pod.metadata.name,
      container,
    };
  });
