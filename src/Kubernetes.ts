import { CoreV1Api, CustomObjectsApi, KubeConfig } from "@kubernetes/client-node";
import { Effect, Either, Schema } from "effect";
import type { KubeTarget } from "./Config.js";
import type { SandboxIdentity } from "./ConnectionState.js";
import { kubectlStderr, kubectlStdout, runCredentialHelper } from "./Runner.js";

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

const config = async (context: string, kubeconfig?: string): Promise<KubeConfig> => {
  const kc = new KubeConfig();
  if (kubeconfig) kc.loadFromFile(kubeconfig);
  else kc.loadFromDefault();
  if (!kc.getContexts().some((candidate) => candidate.name === context)) {
    throw new Error(`context "${context}" not found in kubeconfig`);
  }
  kc.setCurrentContext(context);
  const user = kc.getCurrentUser();
  if (!user?.exec) return kc;
  let exec: Schema.Schema.Type<typeof execSchema>;
  try {
    exec = Schema.decodeUnknownSync(execSchema)(user.exec);
  } catch {
    throw new Error("kubeconfig contains an invalid exec credential helper");
  }
  const result = await Effect.runPromise(Effect.either(runCredentialHelper(exec.command, exec.args ?? [], {
    extraEnv: Object.fromEntries(exec.env?.map(({ name, value }) => [name, value]) ?? []),
    timeoutMs: 60_000,
  })));
  if (Either.isLeft(result)) {
    throw new Error(kubectlStderr(result.left) || kubectlStdout(result.left) || "kubeconfig credential helper failed");
  }
  let credential: Schema.Schema.Type<typeof credentialSchema>;
  try {
    const raw: unknown = JSON.parse(result.right);
    credential = Schema.decodeUnknownSync(credentialSchema)(raw);
  } catch {
    throw new Error("kubeconfig credential helper returned an invalid ExecCredential");
  }
  const status = credential.status;
  if (!status.token && !(status.clientCertificateData && status.clientKeyData)) {
    throw new Error("kubeconfig credential helper returned no usable credentials");
  }
  kc.users = kc.users.map((candidate) => candidate.name === user.name ? {
    ...candidate,
    exec: undefined,
    token: status.token,
    certData: status.clientCertificateData,
    keyData: status.clientKeyData,
  } : candidate);
  return kc;
};

export const resolveSandbox = async (
  target: KubeTarget,
  name: string,
  kubeconfig?: string,
  expectedUid?: string,
): Promise<ResolvedSandbox> => {
  const kc = await config(target.context, kubeconfig);
  const custom = kc.makeApiClient(CustomObjectsApi);
  const core = kc.makeApiClient(CoreV1Api);
  const rawSandbox: unknown = await custom.getNamespacedCustomObject({
    group: "agents.x-k8s.io",
    version: "v1beta1",
    namespace: target.namespace,
    plural: "sandboxes",
    name,
  });
  const sandbox = Schema.decodeUnknownSync(sandboxSchema)(rawSandbox);
  if (expectedUid && sandbox.metadata.uid !== expectedUid) {
    throw new Error(
      `sandbox ${target.namespace}/${name} was replaced: expected UID ${expectedUid}, found ${sandbox.metadata.uid}`,
    );
  }
  if (!sandbox.status.conditions.some((condition) => condition.type === "Ready" && condition.status === "True")) {
    throw new Error(`sandbox ${target.namespace}/${name} is not ready`);
  }
  const rawPods: unknown = await core.listNamespacedPod({
    namespace: target.namespace,
    labelSelector: sandbox.status.selector,
  });
  const pods = Schema.decodeUnknownSync(podListSchema)(rawPods).items.filter((pod) =>
    pod.metadata.ownerReferences.some((owner) => owner.controller === true && owner.uid === sandbox.metadata.uid),
  );
  if (pods.length !== 1) {
    throw new Error(`sandbox ${target.namespace}/${name} owns ${pods.length} matching pods; expected exactly one`);
  }
  const pod = pods[0]!;
  const preferred = pod.metadata.annotations?.["kubectl.kubernetes.io/default-container"];
  const container = preferred ?? (pod.spec.containers.length === 1 ? pod.spec.containers[0]!.name : undefined);
  if (!container || !pod.spec.containers.some((candidate) => candidate.name === container)) {
    throw new Error(`pod ${target.namespace}/${pod.metadata.name} has no unambiguous default container`);
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
};
