import { FileSystem } from "@effect/platform";
import { Effect } from "effect";
import * as Os from "node:os";
import * as Path from "node:path";
import type { KubeTarget } from "./config.js";
import {
  connectionPath,
  defaultStateDir,
  listConnections,
  saveConnection,
  type Connection,
} from "./connection-state.js";
import { disableMachine, ensureMachine } from "./herdr.js";
import { resolveSandbox } from "./kubernetes.js";
import { kubectlStderr, kubectlStdout, runKubectl } from "./runner.js";
import { ensureSshFiles, normalizeHostKey } from "./ssh.js";

export interface ConnectOptions {
  readonly name?: string;
  readonly expectedUid?: string;
  readonly identityFile?: string;
  readonly stateDir?: string;
  readonly kubeconfig?: string;
  readonly kubectl?: string;
  readonly nodePath: string;
  readonly cliPath: string;
}

const selectConnection = (
  target: KubeTarget | undefined,
  stateDir: string,
  name?: string,
): Effect.Effect<{ file: string; connection: Connection } | undefined, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const matches = (yield* listConnections(stateDir)).filter(({ connection }) =>
      (target === undefined || (
        connection.sandbox.context === target.context &&
        connection.sandbox.namespace === target.namespace
      )) &&
      (name === undefined || connection.sandbox.name === name),
    );
    if (matches.length > 1) {
      return yield* Effect.fail(new Error("multiple saved sandboxes match; specify a sandbox name"));
    }
    return matches[0];
  });

const pin = (
  context: string,
  namespace: string,
  pod: string,
  container: string,
  kubectl: string | undefined,
  kubeconfig: string | undefined,
): Effect.Effect<string, Error> =>
  runKubectl([
    "--context", context,
    "--namespace", namespace,
    "exec", pod,
    "-c", container,
    "--", "cat", "/home/agent/.ssh/ssh_host_ed25519_key.pub",
  ], {
    kubectlPath: kubectl,
    kubeconfig,
    timeoutMs: 15_000,
  }).pipe(
    Effect.mapError((error) => new Error(kubectlStderr(error) || kubectlStdout(error) || "kubectl exec failed")),
    Effect.flatMap((hostKey) => Effect.try(() => normalizeHostKey(hostKey))),
  );

const accessPaths = (saved: Connection | undefined, options: ConnectOptions) => ({
  kubeconfig: saved?.kubeconfig ?? options.kubeconfig,
  kubectl: saved?.kubectl ?? options.kubectl,
});

export const connect = (
  target: KubeTarget,
  options: ConnectOptions,
): Effect.Effect<Connection, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const stateDir = options.stateDir ?? defaultStateDir();
    const saved = yield* selectConnection(target, stateDir, options.name);
    if (!saved && !options.name) return yield* Effect.fail(new Error("specify a sandbox name for the first connection"));
    if (!saved && !options.identityFile) return yield* Effect.fail(new Error("specify --identity for the first connection"));
    if (saved && options.identityFile && Path.resolve(options.identityFile) !== saved.connection.ssh.identityFile) {
      return yield* Effect.fail(new Error("the saved connection uses a different SSH identity file"));
    }
    const name = saved?.connection.sandbox.name ?? options.name!;
    const expectedUid = saved?.connection.sandbox.uid ?? options.expectedUid;
    const paths = accessPaths(saved?.connection, options);
    const resolved = yield* resolveSandbox(target, name, paths.kubeconfig ?? undefined, expectedUid);
    const currentPin = yield* pin(
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
      const fs = yield* FileSystem.FileSystem;
      const uid = resolved.identity.uid;
      const sshDir = Path.join(Path.dirname(stateDir), "ssh");
      const identityFile = yield* fs.realPath(Path.resolve(options.identityFile!));
      yield* fs.access(identityFile);
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
      yield* saveConnection(file, connection);
    }
    if (currentPin !== connection.ssh.hostKey) {
      return yield* Effect.fail(new Error(
        `SSH host key mismatch for sandbox ${target.namespace}/${name}; refusing to replace the saved pin`,
      ));
    }
    yield* ensureSshFiles(connection, file, options.nodePath, options.cliPath);
    const profileId = yield* ensureMachine(connection);
    if (connection.phase === "connected") return connection;
    const connected: Connection = { ...connection, phase: "connected", profileId };
    yield* saveConnection(file, connected);
    return connected;
  });

export const disconnect = (
  name?: string,
  stateDir = defaultStateDir(),
): Effect.Effect<Connection, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const saved = yield* selectConnection(undefined, stateDir, name);
    if (!saved) return yield* Effect.fail(new Error("no saved Kubeflock connection matches this target"));
    if (saved.connection.phase === "connected") yield* disableMachine(saved.connection);
    return saved.connection;
  });
