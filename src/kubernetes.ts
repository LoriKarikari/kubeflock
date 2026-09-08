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

const metadataSchema = Schema.Struct({
  name: Schema.String,
  namespace: Schema.String,
  uid: Schema.String,
  labels: Schema.optional(Schema.Record({ key: Schema.String, value: Schema.String })),
  ownerReferences: Schema.optional(Schema.Array(Schema.Struct({
    uid: Schema.String,
    controller: Schema.optional(Schema.Boolean),
  }))),
});

const conditionSchema = Schema.Struct({
  type: Schema.String,
  status: Schema.String,
  reason: Schema.optional(Schema.String),
  message: Schema.optional(Schema.String),
});

const claimSchema = Schema.Struct({
  metadata: metadataSchema,
  spec: Schema.Struct({ warmPoolRef: Schema.Struct({ name: Schema.String }) }),
  status: Schema.optional(Schema.Struct({
    conditions: Schema.optional(Schema.Array(conditionSchema)),
    sandbox: Schema.optional(Schema.Struct({ name: Schema.optional(Schema.String) })),
  })),
});

const claimListSchema = Schema.Struct({ items: Schema.Array(claimSchema) });

const securityContextSchema = Schema.Struct({
  runAsNonRoot: Schema.optional(Schema.Boolean),
  runAsUser: Schema.optional(Schema.Number),
  runAsGroup: Schema.optional(Schema.Number),
  fsGroup: Schema.optional(Schema.Number),
  allowPrivilegeEscalation: Schema.optional(Schema.Boolean),
  capabilities: Schema.optional(Schema.Struct({ drop: Schema.optional(Schema.Array(Schema.String)) })),
  seccompProfile: Schema.optional(Schema.Struct({ type: Schema.String })),
});

const containerSchema = Schema.Struct({
  securityContext: Schema.optional(securityContextSchema),
  ports: Schema.optional(Schema.Array(Schema.Struct({ containerPort: Schema.Number }))),
  resources: Schema.optional(Schema.Struct({
    requests: Schema.optional(Schema.Struct({ cpu: Schema.String, memory: Schema.String })),
    limits: Schema.optional(Schema.Struct({ cpu: Schema.String, memory: Schema.String })),
  })),
  volumeMounts: Schema.optional(Schema.Array(Schema.Struct({ name: Schema.String, mountPath: Schema.String }))),
});

const templateSchema = Schema.Struct({
  metadata: metadataSchema,
  spec: Schema.Struct({
    networkPolicyManagement: Schema.optional(Schema.String),
    podTemplate: Schema.Struct({ spec: Schema.Struct({
      runtimeClassName: Schema.optional(Schema.String),
      automountServiceAccountToken: Schema.optional(Schema.Boolean),
      securityContext: Schema.optional(securityContextSchema),
      containers: Schema.Array(containerSchema),
      volumes: Schema.Array(Schema.Struct({
        name: Schema.String,
        persistentVolumeClaim: Schema.optional(Schema.Struct({ claimName: Schema.String })),
      })),
    }) }),
    volumeClaimTemplates: Schema.Array(Schema.Struct({
      metadata: Schema.Struct({ name: Schema.String }),
      spec: Schema.Struct({
        storageClassName: Schema.String,
        resources: Schema.Struct({ requests: Schema.Struct({ storage: Schema.String }) }),
      }),
    })),
  }),
});

const warmPoolListSchema = Schema.Struct({
  items: Schema.Array(Schema.Struct({
    metadata: metadataSchema,
    spec: Schema.Struct({
      replicas: Schema.optional(Schema.Number),
      sandboxTemplateRef: Schema.Struct({ name: Schema.String }),
    }),
  })),
});

const pvcSchema = Schema.Struct({
  metadata: metadataSchema,
  spec: Schema.Struct({ storageClassName: Schema.String }),
  status: Schema.optional(Schema.Struct({ capacity: Schema.optional(Schema.Struct({ storage: Schema.String })) })),
});

export type SandboxClaim = Schema.Schema.Type<typeof claimSchema>;
export type SandboxCondition = Schema.Schema.Type<typeof conditionSchema>;

export interface ApprovedTemplate {
  readonly name: string;
  readonly warmPool: string;
  readonly homeTemplate: string;
  readonly homeCapacity: string;
  readonly homeStorageClass: string;
}

export interface PersistentHome {
  readonly name: string;
  readonly uid: string;
  readonly capacity: string;
  readonly storageClass: string;
}

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

const validateTemplate = (
  template: Schema.Schema.Type<typeof templateSchema>,
  warmPool: string,
): ApprovedTemplate => {
  const pod = template.spec.podTemplate.spec;
  const podSecurity = pod.securityContext;
  if (
    pod.runtimeClassName !== "gvisor"
    || pod.automountServiceAccountToken !== false
    || podSecurity?.runAsNonRoot !== true
    || podSecurity.runAsUser !== 1000
    || podSecurity.runAsGroup !== 1000
    || podSecurity.fsGroup !== 1000
    || podSecurity.seccompProfile?.type !== "RuntimeDefault"
    || template.spec.networkPolicyManagement === "Unmanaged"
  ) throw new Error(`SandboxTemplate ${template.metadata.name} does not meet Kubeflock pod hardening requirements`);

  for (const container of pod.containers) {
    const security = container.securityContext;
    if (
      security?.allowPrivilegeEscalation !== false
      || security.runAsNonRoot !== true
      || security.runAsUser !== 1000
      || security.seccompProfile?.type !== "RuntimeDefault"
      || !security.capabilities?.drop?.includes("ALL")
      || !container.resources?.requests
      || !container.resources.limits
    ) throw new Error(`SandboxTemplate ${template.metadata.name} contains an unhardened or unbudgeted container`);
  }

  const sshContainer = pod.containers.find((container) =>
    container.ports?.some((port) => port.containerPort === 2222)
    && container.volumeMounts?.some((mount) => mount.mountPath === "/home/agent"),
  );
  const mount = sshContainer?.volumeMounts?.find((candidate) => candidate.mountPath === "/home/agent");
  const volume = pod.volumes.find((candidate) => candidate.name === mount?.name);
  const homeTemplate = template.spec.volumeClaimTemplates.find(
    (candidate) => candidate.metadata.name === volume?.persistentVolumeClaim?.claimName,
  );
  if (!sshContainer || !homeTemplate) {
    throw new Error(`SandboxTemplate ${template.metadata.name} must expose SSH on 2222 and mount a persistent home at /home/agent`);
  }
  return {
    name: template.metadata.name,
    warmPool,
    homeTemplate: homeTemplate.metadata.name,
    homeCapacity: homeTemplate.spec.resources.requests.storage,
    homeStorageClass: homeTemplate.spec.storageClassName,
  };
};

export const resolveApprovedTemplate = (
  target: KubeTarget,
  name: string,
  kubeconfig?: string,
): Effect.Effect<ApprovedTemplate, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const custom = kc.makeApiClient(CustomObjectsApi);
    const templateRaw: unknown = yield* Effect.tryPromise({
      try: () => custom.getNamespacedCustomObject({
        group: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxtemplates",
        name,
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const template = yield* Schema.decodeUnknown(templateSchema)(templateRaw);
    const poolsRaw: unknown = yield* Effect.tryPromise({
      try: () => custom.listNamespacedCustomObject({
        group: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxwarmpools",
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const pools = yield* Schema.decodeUnknown(warmPoolListSchema)(poolsRaw);
    const matches = pools.items.filter((pool) => pool.spec.sandboxTemplateRef.name === name);
    if (matches.length !== 1) {
      return yield* Effect.fail(new Error(`SandboxTemplate ${name} must have exactly one SandboxWarmPool; found ${matches.length}`));
    }
    if (matches[0]!.spec.replicas !== 0) {
      return yield* Effect.fail(new Error(`SandboxWarmPool ${matches[0]!.metadata.name} must have zero warm standbys for cold creation`));
    }
    return yield* Effect.try({
      try: () => validateTemplate(template, matches[0]!.metadata.name),
      catch: (error) => error instanceof Error ? error : new Error("SandboxTemplate validation failed"),
    });
  });

export const getSandboxClaim = (
  target: KubeTarget,
  name: string,
  kubeconfig?: string,
): Effect.Effect<SandboxClaim | undefined, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const custom = kc.makeApiClient(CustomObjectsApi);
    const raw: unknown = yield* Effect.tryPromise({
      try: () => custom.listNamespacedCustomObject({
        group: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxclaims",
        fieldSelector: `metadata.name=${name}`,
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const claims = (yield* Schema.decodeUnknown(claimListSchema)(raw)).items;
    if (claims.length > 1) return yield* Effect.fail(new Error(`multiple SandboxClaims named ${name}`));
    return claims[0];
  });

export const createSandboxClaim = (
  target: KubeTarget,
  name: string,
  warmPool: string,
  kubeconfig?: string,
): Effect.Effect<SandboxClaim, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const custom = kc.makeApiClient(CustomObjectsApi);
    const raw: unknown = yield* Effect.tryPromise({
      try: () => custom.createNamespacedCustomObject({
        group: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxclaims",
        body: {
          apiVersion: "extensions.agents.x-k8s.io/v1beta1",
          kind: "SandboxClaim",
          metadata: {
            name,
            namespace: target.namespace,
            labels: { "app.kubernetes.io/managed-by": "kubeflock" },
          },
          spec: { warmPoolRef: { name: warmPool } },
        },
        fieldManager: "kubeflock",
        fieldValidation: "Strict",
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    return yield* Schema.decodeUnknown(claimSchema)(raw);
  });

export const resolvePersistentHome = (
  target: KubeTarget,
  sandbox: SandboxIdentity,
  homeTemplate: string,
  kubeconfig?: string,
): Effect.Effect<PersistentHome, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const core = kc.makeApiClient(CoreV1Api);
    const raw: unknown = yield* Effect.tryPromise({
      try: () => core.readNamespacedPersistentVolumeClaim({
        namespace: target.namespace,
        name: `${homeTemplate}-${sandbox.name}`,
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    const pvc = yield* Schema.decodeUnknown(pvcSchema)(raw);
    const owned = pvc.metadata.ownerReferences?.some((owner) => owner.uid === sandbox.uid && owner.controller === true);
    if (!owned) return yield* Effect.fail(new Error(`PersistentVolumeClaim ${pvc.metadata.name} is not owned by Sandbox UID ${sandbox.uid}`));
    return {
      name: pvc.metadata.name,
      uid: pvc.metadata.uid,
      capacity: pvc.status?.capacity?.storage ?? "unknown",
      storageClass: pvc.spec.storageClassName,
    };
  });

export const listSandboxClaims = (
  target: KubeTarget,
  kubeconfig?: string,
): Effect.Effect<ReadonlyArray<SandboxClaim>, Error> =>
  Effect.gen(function*() {
    const kc = yield* config(target.context, kubeconfig);
    const custom = kc.makeApiClient(CustomObjectsApi);
    const raw: unknown = yield* Effect.tryPromise({
      try: () => custom.listNamespacedCustomObject({
        group: "extensions.agents.x-k8s.io",
        version: "v1beta1",
        namespace: target.namespace,
        plural: "sandboxclaims",
        labelSelector: "app.kubernetes.io/managed-by=kubeflock",
      }),
      catch: (error) => error instanceof Error ? error : new Error("Kubernetes request failed"),
    });
    return (yield* Schema.decodeUnknown(claimListSchema)(raw)).items;
  });
