import { Effect, Either } from "effect";
import { access, realpath } from "node:fs/promises";
import * as Os from "node:os";
import * as Path from "node:path";
import type { KubeTarget } from "./Config.js";
import {
  connectionPath,
  defaultStateDir,
  listConnections,
  saveConnection,
  type Connection,
} from "./ConnectionState.js";
import { disableMachine, ensureMachine } from "./Herdr.js";
import { resolveSandbox } from "./Kubernetes.js";
import { kubectlStderr, kubectlStdout, runKubectl } from "./Runner.js";
import { ensureSshFiles, normalizeHostKey } from "./SSH.js";

export interface ConnectOptions {
  readonly name?: string;
  readonly identityFile?: string;
  readonly stateDir?: string;
  readonly kubeconfig?: string;
  readonly kubectl?: string;
  readonly nodePath: string;
  readonly cliPath: string;
}

const selectConnection = async (
  target: KubeTarget | undefined,
  stateDir: string,
  name?: string,
): Promise<{ file: string; connection: Connection } | undefined> => {
  const matches = (await listConnections(stateDir)).filter(({ connection }) =>
    (target === undefined || (
      connection.sandbox.context === target.context &&
      connection.sandbox.namespace === target.namespace
    )) &&
    (name === undefined || connection.sandbox.name === name),
  );
  if (matches.length > 1) throw new Error("multiple saved sandboxes match; specify a sandbox name");
  return matches[0];
};

const pin = async (
  context: string,
  namespace: string,
  pod: string,
  container: string,
  kubectl: string | undefined,
  kubeconfig: string | undefined,
): Promise<string> => {
  const result = await Effect.runPromise(Effect.either(runKubectl([
    "--context", context,
    "--namespace", namespace,
    "exec", pod,
    "-c", container,
    "--", "cat", "/home/agent/.ssh/ssh_host_ed25519_key.pub",
  ], {
    kubectlPath: kubectl,
    kubeconfig,
    timeoutMs: 15_000,
  })));
  if (Either.isLeft(result)) {
    throw new Error(kubectlStderr(result.left) || kubectlStdout(result.left) || "kubectl exec failed");
  }
  return normalizeHostKey(result.right);
};

const accessPaths = (saved: Connection | undefined, options: ConnectOptions) => ({
  kubeconfig: saved?.kubeconfig ?? options.kubeconfig,
  kubectl: saved?.kubectl ?? options.kubectl,
});

export const connect = async (target: KubeTarget, options: ConnectOptions): Promise<Connection> => {
  const stateDir = options.stateDir ?? defaultStateDir();
  const saved = await selectConnection(target, stateDir, options.name);
  if (!saved && !options.name) throw new Error("specify a sandbox name for the first connection");
  if (!saved && !options.identityFile) throw new Error("specify --identity for the first connection");
  if (saved && options.identityFile && Path.resolve(options.identityFile) !== saved.connection.ssh.identityFile) {
    throw new Error("the saved connection uses a different SSH identity file");
  }
  const name = saved?.connection.sandbox.name ?? options.name!;
  const paths = accessPaths(saved?.connection, options);
  const resolved = await resolveSandbox(target, name, paths.kubeconfig ?? undefined, saved?.connection.sandbox.uid);
  const currentPin = await pin(
    target.context,
    target.namespace,
    resolved.pod,
    resolved.container,
    paths.kubectl,
    paths.kubeconfig ?? undefined,
  );
  let file: string;
  let connection: Connection;
  if (saved) {
    file = saved.file;
    connection = saved.connection;
  } else {
    const uid = resolved.identity.uid;
    const sshDir = Path.join(Path.dirname(stateDir), "ssh");
    const identityFile = await realpath(Path.resolve(options.identityFile!));
    await access(identityFile);
    file = connectionPath(stateDir, uid);
    connection = {
      version: 1,
      phase: "prepared",
      sandbox: resolved.identity,
      ssh: {
        alias: `kubeflock-${uid}`,
        identityFile,
        knownHostsFile: Path.join(sshDir, `${uid}.known_hosts`),
        entryFile: Path.join(sshDir, `${uid}.conf`),
        proxyFile: Path.join(sshDir, `${uid}-proxy`),
        configFile: process.env["KUBEFLOCK_SSH_CONFIG"] ?? Path.join(Os.homedir(), ".ssh", "config"),
        hostKey: currentPin,
      },
      herdr: { label: `Kubeflock: ${name} [${uid.slice(0, 8)}]`, session: "agent" },
      kubeconfig: options.kubeconfig ?? null,
      kubectl: options.kubectl ?? process.env["KUBEFLOCK_KUBECTL"] ?? "kubectl",
    };
    await saveConnection(file, connection);
  }
  if (currentPin !== connection.ssh.hostKey) {
    throw new Error(`SSH host key mismatch for sandbox ${target.namespace}/${name}; refusing to replace the saved pin`);
  }
  await ensureSshFiles(connection, file, options.nodePath, options.cliPath);
  const profileId = await ensureMachine(connection);
  if (connection.phase === "connected") return connection;
  const connected: Connection = { ...connection, phase: "connected", profileId };
  await saveConnection(file, connected);
  return connected;
};

export const disconnect = async (name?: string, stateDir = defaultStateDir()): Promise<Connection> => {
  const saved = await selectConnection(undefined, stateDir, name);
  if (!saved) throw new Error("no saved Kubeflock connection matches this target");
  if (saved.connection.phase === "connected") await disableMachine(saved.connection);
  return saved.connection;
};
