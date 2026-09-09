import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseAllDocuments } from "yaml";

const chart = fileURLToPath(new URL("../charts/kubeflock", import.meta.url));
const values = fileURLToPath(new URL("../charts/kubeflock/values.example.yaml", import.meta.url));

const helm = (...args: ReadonlyArray<string>) =>
  spawnSync("helm", args, { encoding: "utf8", timeout: 10_000 });

const render = (...args: ReadonlyArray<string>): Array<Record<string, unknown>> => {
  const result = helm("template", "kubeflock", chart, "--namespace", "developer", "--values", values, ...args);
  expect(result.stderr).toBe("");
  expect(result.status).toBe(0);
  return parseAllDocuments(result.stdout).map((document) => document.toJSON() as Record<string, unknown>);
};

const resource = (items: ReadonlyArray<Record<string, unknown>>, kind: string) => {
  const found = items.find((item) => item["kind"] === kind);
  expect(found).toBeDefined();
  return found!;
};

describe("Kubeflock chart", () => {
  it("renders the isolated namespace, budgets, access, template, and cold pool", () => {
    const items = render();
    expect(items.map((item) => item["kind"])).toEqual([
      "Namespace",
      "NetworkPolicy",
      "ResourceQuota",
      "LimitRange",
      "ClusterRole",
      "ClusterRoleBinding",
      "Role",
      "RoleBinding",
      "SandboxTemplate",
      "SandboxWarmPool",
    ]);

    const namespace = resource(items, "Namespace") as {
      metadata: { labels: Record<string, string>; annotations: Record<string, string> };
    };
    expect(namespace.metadata.labels["pod-security.kubernetes.io/enforce"]).toBe("restricted");
    expect(namespace.metadata.annotations["helm.sh/resource-policy"]).toBe("keep");

    const quota = resource(items, "ResourceQuota") as {
      metadata: { annotations: Record<string, string> };
      spec: { hard: Record<string, string> };
    };
    expect(quota.metadata.annotations["helm.sh/resource-policy"]).toBe("keep");
    expect(quota.spec.hard).toEqual({
      pods: "2",
      persistentvolumeclaims: "4",
      "requests.cpu": "1000m",
      "limits.cpu": "4000m",
      "requests.memory": "2048Mi",
      "limits.memory": "8192Mi",
      "requests.storage": "40Gi",
    });

    const template = resource(items, "SandboxTemplate") as {
      spec: {
        podTemplate: { spec: {
          runtimeClassName: string;
          automountServiceAccountToken: boolean;
          securityContext: Record<string, unknown>;
          containers: Array<{ securityContext: Record<string, unknown> }>;
        } };
        volumeClaimTemplates: Array<{ spec: { storageClassName: string } }>;
      };
    };
    const pod = template.spec.podTemplate.spec;
    expect(pod.runtimeClassName).toBe("gvisor");
    expect(pod.automountServiceAccountToken).toBe(false);
    expect(pod.securityContext).toMatchObject({ runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000 });
    expect(pod.containers[0].securityContext).toMatchObject({
      allowPrivilegeEscalation: false,
      capabilities: { drop: ["ALL"] },
    });
    expect(template.spec.volumeClaimTemplates[0].spec.storageClassName).toBe("standard");

    const pool = resource(items, "SandboxWarmPool") as { spec: Record<string, unknown> };
    expect(pool.spec).toEqual({ replicas: 0, sandboxTemplateRef: { name: "dev-small" } });
  });

  it("grants only permissions used by current commands", () => {
    const rules = (resource(render(), "Role") as {
      rules: Array<{ apiGroups: Array<string>; resources: Array<string>; verbs: Array<string> }>;
    }).rules;
    expect(rules.flatMap((rule) => rule.verbs)).not.toContain("delete");
    expect(rules.flatMap((rule) => rule.verbs)).not.toContain("patch");
    expect(rules.flatMap((rule) => rule.resources)).not.toContain("secrets");
    expect(rules).toContainEqual({ apiGroups: [""], resources: ["pods/exec"], verbs: ["create"] });
  });

  it("requires explicit access, image, SSH, and storage values", () => {
    const result = helm("template", "kubeflock", chart, "--namespace", "developer");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("access.subjects");
    expect(result.stderr).toContain("sandbox.image");
    expect(result.stderr).toContain("sandbox.sshPublicKey");
    expect(result.stderr).toContain("sandbox.storage.className");
  });

  it("rejects capacity that cannot retain every active home", () => {
    const result = helm(
      "template", "kubeflock", chart, "--namespace", "developer", "--values", values,
      "--set", "capacity.maxRetainedHomes=1",
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("maxRetainedHomes cannot be less than maxActiveSandboxes");
  });

  it("does not own the controller, active sandboxes, or homes", () => {
    const kinds = render().map((item) => item["kind"]);
    for (const kind of ["CustomResourceDefinition", "Deployment", "Sandbox", "SandboxClaim", "PersistentVolumeClaim"]) {
      expect(kinds).not.toContain(kind);
    }
  });
});
