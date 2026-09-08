import { Effect } from "effect";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as Path from "node:path";
import { describe, expect, it } from "vitest";
import { runCheck } from "../src/check.js";

const fakeKubectl = (dir: string, logPath: string): string => {
  const script = `#!/bin/sh
LOG="${logPath}"
printf '%s\\n' "$*" >> "$LOG"
if [ -n "$EXPECTED_CONTEXT" ]; then
  case "$*" in
    *"--context $EXPECTED_CONTEXT"*) ;;
    *) echo "wrong context: $* (want $EXPECTED_CONTEXT)" >&2; exit 1 ;;
  esac
fi
case "$*" in
  *"api-versions"*)
    if [ -n "$ALPHA_ONLY" ]; then
      echo "v1"; echo "agents.x-k8s.io/v1alpha1"; echo "extensions.agents.x-k8s.io/v1alpha1"; exit 0
    fi
    echo "v1"; echo "agents.x-k8s.io/v1beta1"; echo "extensions.agents.x-k8s.io/v1beta1"; exit 0 ;;
  *"auth can-i"*)
    if [ -n "$DENY_ALL" ]; then echo "no"; exit 1; fi
    echo "yes"; exit 0 ;;
  *"api-resources"*"extensions.agents.x-k8s.io"*)
    echo "sandboxclaims"; echo "sandboxtemplates"; echo "sandboxwarmpools"; exit 0 ;;
  *"api-resources"*"agents.x-k8s.io"*)
    echo "sandboxes"; exit 0 ;;
  *"get runtimeclass"*)
    if [ -n "$LONG_TOKEN_LEAK" ]; then
      echo 'eyJ${"A".repeat(30)}.REPORT_JWT_PAYLOAD${"A".repeat(600)}.${"A".repeat(40)}' >&2; exit 1
    fi
    if [ -n "$TOKEN_LEAK" ]; then
      echo 'access_token="REPORT_TOKEN_XYZ"' >&2; exit 1
    fi
    echo '{"metadata":{"name":"gvisor"},"handler":"runsc"}'; exit 0 ;;
  *"get storageclass"*)
    echo '{"items":[{"metadata":{"name":"longhorn","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"driver.longhorn.io"}]}'; exit 0 ;;
  *"get namespace"*)
    echo '{"metadata":{"name":"ns"}}'; exit 0 ;;
  *"get resourcequota"*)
    if [ -n "$CONFIGMAP_ONLY" ]; then
      echo '{"items":[{"metadata":{"name":"thin"},"spec":{"hard":{"count/configmaps":"5"}}}]}'; exit 0
    fi
    echo '{"items":[{"metadata":{"name":"quota"},"spec":{"hard":{"pods":"1","requests.cpu":"1","requests.memory":"1Gi","requests.storage":"1Gi","persistentvolumeclaims":"1"}}}]}'; exit 0 ;;
  *"get limitrange"*)
    echo '{"items":[{}]}'; exit 0 ;;
esac
echo "unexpected kubectl call: $*" >&2; exit 1
`;
  const p = Path.join(dir, "kubectl");
  writeFileSync(p, script, { mode: 0o755 });
  return p;
};

const runWithFake = async (extraEnv: NodeJS.ProcessEnv) => {
  const dir = mkdtempSync(Path.join(tmpdir(), "kf-check-"));
  try {
    const logPath = Path.join(dir, "calls.log");
    const bin = fakeKubectl(dir, logPath);
    const report = await Effect.runPromise(
      runCheck({ context: "saved", namespace: "dev-ns" }, {
        kubectlPath: bin,
        requestTimeoutSec: 2,
        extraEnv: { ...extraEnv, EXPECTED_CONTEXT: "saved" },
        now: () => new Date("2026-09-08T00:00:00.000Z"),
      }),
    );
    return { report, log: readFileSync(logPath, "utf8") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

describe("explicit context", () => {
  it("passes the saved context to every probe", async () => {
    const { report, log } = await runWithFake({});
    expect(report.ok).toBe(true);
    expect(log).toContain("--context saved");
  });
});

describe("permissions", () => {
  it("reports denied access with a fix", async () => {
    const { report } = await runWithFake({ DENY_ALL: "1" });
    expect(report.ok).toBe(false);
    const permissions = report.checks.filter((c) => c.name.startsWith("perm-"));
    expect(permissions.length).toBeGreaterThan(0);
    for (const c of permissions) {
      expect(c.ok).toBe(false);
      expect(c.category).toBe("denied");
      expect(c.remediation).toBeTruthy();
    }
  });

  it("probes exec and log as subresources, not named pods", async () => {
    const { log } = await runWithFake({});
    expect(log).toContain("auth can-i create pods --subresource=exec");
    expect(log).toContain("auth can-i get pods --subresource=log");
    expect(log).not.toContain("pods/exec");
    expect(log).not.toContain("pods/log");
  });
});

describe("served versions", () => {
  it("fails when only alpha versions are served", async () => {
    const { report } = await runWithFake({ ALPHA_ONLY: "1" });
    expect(report.ok).toBe(false);
    for (const name of ["agents-api", "extensions-api"]) {
      const found = report.checks.find((c) => c.name === name);
      expect(found?.ok).toBe(false);
      expect(found?.category).toBe("missing-infrastructure");
    }
  });
});

describe("budgets", () => {
  it("fails a quota with no compute or storage", async () => {
    const { report } = await runWithFake({ CONFIGMAP_ONLY: "1" });
    expect(report.ok).toBe(false);
    const quota = report.checks.find((c) => c.name === "budgets-quota");
    expect(quota?.ok).toBe(false);
    expect(quota?.category).toBe("missing-infrastructure");
  });
});

describe("credential redaction", () => {
  it("redacts long JWTs before shortening diagnostics", async () => {
    const { report } = await runWithFake({ LONG_TOKEN_LEAK: "1" });
    const output = JSON.stringify(report);
    expect(output).not.toContain("REPORT_JWT_PAYLOAD");
    expect(output).toContain("[redacted-jwt]");
  });

  it("keeps quoted tokens out of the report", async () => {
    const { report } = await runWithFake({ TOKEN_LEAK: "1" });
    for (const c of report.checks) {
      expect(c.message).not.toContain("REPORT_TOKEN_XYZ");
    }
  });
});

describe("read-only contract", () => {
  it("issues no cluster writes", async () => {
    const { log } = await runWithFake({});
    const allowed = new Set(["api-versions", "api-resources", "get", "auth"]);
    for (const line of log.trim().split("\n")) {
      const fields = line.split(/\s+/);
      let command: Array<string> = [];
      for (let i = 0; i < fields.length; i++) {
        const f = fields[i]!;
        if (f === "--context" || f === "-n" || f === "--request-timeout") {
          i++;
          continue;
        }
        if (f.startsWith("-")) continue;
        command = fields.slice(i);
        break;
      }
      expect(allowed.has(command[0]!)).toBe(true);
      if (command[0] === "auth") expect(command[1]).toBe("can-i");
    }
  });
});
