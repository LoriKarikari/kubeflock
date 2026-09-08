import { Effect, Exit, Fiber } from "effect";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as Path from "node:path";
import { describe, expect, it } from "vitest";
import { runKubectl } from "./Runner.js";

const writeExe = (dir: string, name: string, body: string): string => {
  const p = Path.join(dir, name);
  writeFileSync(p, body, { mode: 0o755 });
  return p;
};

describe("runner", () => {
  it("returns stdout on success", async () => {
    const dir = mkdtempSync(Path.join(tmpdir(), "kf-run-"));
    try {
      const fake = writeExe(dir, "kubectl", "#!/bin/sh\necho hello-stdout\n");
      const out = await Effect.runPromise(runKubectl(["get", "pods"], { kubectlPath: fake, timeoutMs: 5000 }));
      expect(out.trim()).toBe("hello-stdout");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports a missing binary as a spawn error", async () => {
    const err = await Effect.runPromise(
      Effect.match(runKubectl(["get", "pods"], { kubectlPath: "/nonexistent/kubectl", timeoutMs: 5000 }), {
        onFailure: (e) => e,
        onSuccess: () => null,
      }),
    );
    expect(err?._tag).toBe("KubectlSpawnError");
  });

  it("kills a helper that ignores SIGTERM", async () => {
    const dir = mkdtempSync(Path.join(tmpdir(), "kf-run-"));
    try {
      const childFile = Path.join(dir, "child.pid");
      const fake = writeExe(
        dir,
        "kubectl",
        `#!/bin/sh\necho $$ > "${dir}/parent.pid"\n( trap '' TERM; exec sleep 30 ) &\necho $! > "${childFile}"\ntrap '' TERM\nexec sleep 30\n`,
      );
      const start = Date.now();
      const err = await Effect.runPromise(
        Effect.match(runKubectl(["--context", "saved", "get", "pods"], { kubectlPath: fake, timeoutMs: 600 }), {
          onFailure: (e) => e,
          onSuccess: () => null,
        }),
      );
      expect(err).not.toBeNull();
      expect(err?._tag).toBe("KubectlTimeoutError");
      expect(Date.now() - start).toBeLessThan(10000);
      // The helper must be gone: nothing may keep the OIDC lock.
      const pid = Number(readFileSync(childFile, "utf8").trim());
      const deadline = Date.now() + 3000;
      for (;;) {
        let alive = true;
        try {
          process.kill(pid, 0);
        } catch {
          alive = false;
        }
        if (!alive) break;
        if (Date.now() > deadline) throw new Error(`helper child ${pid} still alive after timeout`);
        await new Promise((r) => setTimeout(r, 50));
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("cleans the group on interruption", async () => {
    const dir = mkdtempSync(Path.join(tmpdir(), "kf-run-"));
    try {
      const pidFile = Path.join(dir, "parent.pid");
      const fake = writeExe(dir, "kubectl", `#!/bin/sh\necho $$ > "${pidFile}"\nexec sleep 30\n`);
      const fiber = Effect.runFork(runKubectl(["get", "pods"], { kubectlPath: fake, timeoutMs: 30000 }));
      await new Promise((r) => setTimeout(r, 500));
      await Effect.runPromise(Fiber.interrupt(fiber));
      const exit = await Effect.runPromise(Fiber.await(fiber));
      expect(Exit.isFailure(exit)).toBe(true);
      const pid = Number(readFileSync(pidFile, "utf8").trim());
      const deadline = Date.now() + 3000;
      for (;;) {
        let alive = true;
        try {
          process.kill(pid, 0);
        } catch {
          alive = false;
        }
        if (!alive) break;
        if (Date.now() > deadline) throw new Error(`kubectl child ${pid} survived interruption`);
        await new Promise((r) => setTimeout(r, 50));
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
