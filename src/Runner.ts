import { Data, Effect } from "effect";
import { spawn, type ChildProcess } from "node:child_process";

export interface RunOptions {
  readonly kubectlPath?: string;
  readonly kubeconfig?: string;
  readonly extraEnv?: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
}

export class KubectlSpawnError extends Data.TaggedError("KubectlSpawnError")<{
  readonly cause: string;
}> {}

export class KubectlFailedError extends Data.TaggedError("KubectlFailedError")<{
  readonly stderr: string;
  readonly stdout: string;
  readonly exitCode: number | null;
}> {}

export class KubectlTimeoutError extends Data.TaggedError("KubectlTimeoutError")<{
  readonly stderr: string;
  readonly stdout: string;
}> {}

export type KubectlError = KubectlSpawnError | KubectlFailedError | KubectlTimeoutError;

export const kubectlStderr = (err: KubectlError): string => err._tag === "KubectlSpawnError" ? "" : err.stderr;

export const kubectlStdout = (err: KubectlError): string => err._tag === "KubectlSpawnError" ? "" : err.stdout;

const binPath = (explicit?: string): string => explicit ?? process.env["KUBEFLOCK_KUBECTL"] ?? "kubectl";

const killGroup = (pid: number | undefined, signal: NodeJS.Signals): void => {
  if (!pid || pid <= 0) return;
  try {
    process.kill(-pid, signal);
  } catch {
    // Cleanup can race process exit.
  }
};

// kubectl's request timeout does not bound credential helpers holding OIDC locks.
// Scope cleanup kills the group, including helpers that ignore SIGTERM.
const runProcess = (
  command: string,
  args: ReadonlyArray<string>,
  opts: RunOptions,
): Effect.Effect<string, KubectlError> => Effect.suspend(() => {
  let pid: number | undefined;
  let stderr = "";
  let stdout = "";

  const collect = (child: ChildProcess): Effect.Effect<string, KubectlFailedError | KubectlSpawnError> =>
    Effect.async<string, KubectlFailedError | KubectlSpawnError>((resume) => {
      child.stdout?.on("data", (d) => {
        stdout += d.toString();
      });
      child.stderr?.on("data", (d) => {
        stderr += d.toString();
      });
      child.on("error", (err) => {
        resume(Effect.fail(new KubectlSpawnError({ cause: err.message })));
      });
      child.on("close", (code) => {
        if (code === 0) {
          resume(Effect.succeed(stdout));
        } else {
          resume(Effect.fail(new KubectlFailedError({ stderr, stdout, exitCode: code })));
        }
      });
    });

  return Effect.scoped(
    Effect.acquireRelease(
      Effect.sync(() => {
        const env: NodeJS.ProcessEnv = { ...process.env, ...opts.extraEnv };
        if (opts.kubeconfig) env["KUBECONFIG"] = opts.kubeconfig;
        const child = spawn(command, [...args], { detached: true, env });
        pid = child.pid;
        return child;
      }),
      (child) =>
        Effect.sync(() => {
          killGroup(child.pid, "SIGKILL");
        }),
    ).pipe(
      Effect.flatMap(collect),
      Effect.timeoutFail({
        duration: opts.timeoutMs,
        onTimeout: () => {
          killGroup(pid, "SIGTERM");
          return new KubectlTimeoutError({ stderr, stdout });
        },
      }),
    ),
  );
});

export const runKubectl = (
  args: ReadonlyArray<string>,
  opts: RunOptions,
): Effect.Effect<string, KubectlError> => runProcess(binPath(opts.kubectlPath), args, opts);

export const runCredentialHelper = (
  command: string,
  args: ReadonlyArray<string>,
  opts: Omit<RunOptions, "kubectlPath" | "kubeconfig">,
): Effect.Effect<string, KubectlError> => runProcess(command, args, { ...opts });
