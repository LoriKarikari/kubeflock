import { spawn } from "node:child_process";
import { loadConnection } from "./ConnectionState.js";
import { resolveSandbox } from "./Kubernetes.js";

const killGroup = (pid: number | undefined, signal: NodeJS.Signals): void => {
  if (pid === undefined || process.platform === "win32") return;
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) throw error;
  }
};

export const runProxy = async (stateFile: string): Promise<number> => {
  const connection = await loadConnection(stateFile);
  const resolved = await resolveSandbox(
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
    "--", "socat", "STDIO", "TCP:127.0.0.1:2222",
  ];
  if (connection.kubeconfig) args.unshift("--kubeconfig", connection.kubeconfig);
  const child = spawn(connection.kubectl, args, { detached: process.platform !== "win32", stdio: "inherit" });
  const terminate = (): void => killGroup(child.pid, "SIGTERM");
  process.once("SIGINT", terminate);
  process.once("SIGTERM", terminate);
  try {
    return await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
    });
  } finally {
    process.off("SIGINT", terminate);
    process.off("SIGTERM", terminate);
    killGroup(child.pid, "SIGKILL");
  }
};
