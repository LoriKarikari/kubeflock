import { Effect } from "effect";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as Path from "node:path";
import { describe, expect, it } from "vitest";
import { runCheck } from "./Check.js";

// fakeKubectl emulates read-only kubectl responses. It logs every argv line
// and rejects calls missing --context EXPECTED_CONTEXT. DENY_ALL makes every
// `auth can-i` probe answer "no".
const fakeKubectl = (dir: string, logPath: string): string => {
  const script = `#!/bin/sh
LOG="${logPath}"
printf '%s\\n' "$*" >> "$LOG"
if [ -n "$EXPECTED_CONTEXT" ]; then
  case "$*" in
    *"config get-contexts"*) ;;
    *"--context $EXPECTED_CONTEXT"*) ;;
    *) echo "wrong context: $* (want $EXPECTED_CONTEXT)" >&2; exit 1 ;;
  esac
fi
case "$*" in
  *"api-versions"*)
    echo "v1"; echo "agents.x-k8s.io/v1beta1"; echo "extensions.agents.x-k8s.io/v1beta1"; exit 0 ;;
  *"auth can-i"*)
    if [ -n "$DENY_ALL" ]; then echo "no"; exit 0; fi
    echo "yes"; exit 0 ;;
  *"api-resources"*"extensions.agents.x-k8s.io"*)
    echo "sandboxclaims"; echo "sandboxtemplates"; echo "sandboxwarmpools"; exit 0 ;;
  *"api-resources"*"agents.x-k8s.io"*)
    echo "sandboxes"; exit 0 ;;
  *"get runtimeclass"*)
    echo '{"metadata":{"name":"gvisor"},"handler":"runsc"}'; exit 0 ;;
  *"get storageclass"*)
    echo '{"items":[{"metadata":{"name":"longhorn","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}},"provisioner":"driver.longhorn.io"}]}'; exit 0 ;;
  *"get namespace"*)
    echo '{"metadata":{"name":"ns"}}'; exit 0 ;;
  *"get resourcequota"*)
    echo '{"items":[{"metadata":{"name":"quota"}}]}'; exit 0 ;;
  *"get limitrange"*)
    echo '{"items":[{}]}'; exit 0 ;;
  *"config get-contexts"*)
    echo "saved"; echo "other"; exit 0 ;;
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
  it("pins the saved context and ignores current-context", async () => {
    const { report, log } = await runWithFake({});
    expect(report.ok).toBe(true);
    expect(log).toContain("--context saved");
    expect(log).not.toContain("--context other");
    expect(log.trim().split("\n").length).toBeGreaterThan(5);
  });
});

describe("permissions", () => {
  it("reports denied access with a fix", async () => {
    const { report } = await runWithFake({ DENY_ALL: "1" });
    expect(report.ok).toBe(false);
    const denied = report.checks.filter((c) => !c.ok && c.category === "denied");
    expect(denied.length).toBeGreaterThan(0);
    for (const c of denied) expect(c.remediation).not.toBe("");
    for (const c of report.checks) {
      expect(c.message).not.toContain("Bearer");
      expect(c.message).not.toContain("eyJ");
    }
  });
});

describe("read-only contract", () => {
  it("issues no cluster writes", async () => {
    const { log } = await runWithFake({});
    const allowed = new Set(["api-versions", "api-resources", "get", "auth", "config"]);
    for (const line of log.trim().split("\n")) {
      const fields = line.split(/\s+/);
      let sub = "";
      for (let i = 0; i < fields.length; i++) {
        const f = fields[i]!;
        if (f === "--context" || f === "-n" || f === "--request-timeout") {
          i++;
          continue;
        }
        if (f.startsWith("-")) continue;
        sub = f;
        break;
      }
      expect(allowed.has(sub)).toBe(true);
      if (["create", "delete", "patch", "apply", "replace"].includes(sub)) {
        expect(line).toContain("can-i");
      }
    }
  });
});
