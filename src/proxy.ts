import { spawn } from "node:child_process";
import { FileSystem } from "@effect/platform";
import { Effect } from "effect";
import { loadConnection } from "./connection-state.js";
import { resolveSandbox } from "./kubernetes.js";

const killGroup = (pid: number | undefined, signal: NodeJS.Signals): void => {
  if (pid === undefined || process.platform === "win32") return;
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) throw error;
  }
};

const relay = (command: string, args: ReadonlyArray<string>): Effect.Effect<number, Error> =>
  Effect.acquireUseRelease(
    Effect.try({
      try: () => {
        const child = spawn(command, [...args], { detached: process.platform !== "win32", stdio: "inherit" });
        const terminate = (): void => killGroup(child.pid, "SIGTERM");
        process.once("SIGINT", terminate);
        process.once("SIGTERM", terminate);
        return { child, terminate };
      },
      catch: (error) => error instanceof Error ? error : new Error("kubectl proxy failed"),
    }),
    ({ child }) => Effect.async<number, Error>((resume) => {
      child.once("error", (error) => resume(Effect.fail(error)));
      child.once("close", (code, signal) => resume(Effect.succeed(code ?? (signal ? 1 : 0))));
    }),
    ({ child, terminate }) => Effect.sync(() => {
      process.off("SIGINT", terminate);
      process.off("SIGTERM", terminate);
      killGroup(child.pid, "SIGKILL");
    }),
  );

export const runProxy = (stateFile: string): Effect.Effect<number, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const connection = yield* loadConnection(stateFile);
    const resolved = yield* resolveSandbox(
      { context: connection.sandbox.context, namespace: connection.sandbox.namespace },
      connection.sandbox.name,
      connection.kubeconfig ?? undefined,
      connection.sandbox.uid,
    );
    const args = [
      "--context", connection.sandbox.context,
      "--namespace", connection.sandbox.namespace,
      "exec", "-i", resolved.pod,
      "-c", resolved.container,
      "--", "socat", "STDIO", `TCP:127.0.0.1:${resolved.sshPort}`,
    ];
    if (connection.kubeconfig) args.unshift("--kubeconfig", connection.kubeconfig);
    return yield* relay(connection.kubectl, args);
  });
