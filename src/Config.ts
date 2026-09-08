import { Data, Effect } from "effect";
import { FileSystem } from "@effect/platform";
import * as Os from "node:os";
import * as Path from "node:path";
import { parse, stringify } from "yaml";

export interface KubeTarget {
  readonly context: string;
  readonly namespace: string;
}

export class ConfigIOError extends Data.TaggedError("ConfigIOError")<{
  readonly cause: string;
}> {}

export class ConfigParseError extends Data.TaggedError("ConfigParseError")<{
  readonly cause: string;
}> {}

export class ConfigInvalidError extends Data.TaggedError("ConfigInvalidError")<{
  readonly cause: string;
}> {}

export type ConfigError = ConfigIOError | ConfigParseError | ConfigInvalidError;

const namespaceRe = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

// defaultPath is the shared config file for CLI and Herdr actions.
// Precedence: KUBEFLOCK_CONFIG, then XDG_CONFIG_HOME, then ~/.config.
export const defaultPath = (): string => {
  const override = process.env["KUBEFLOCK_CONFIG"];
  if (override) return override;
  const base = process.env["XDG_CONFIG_HOME"] ?? Path.join(Os.homedir(), ".config");
  return Path.join(base, "kubeflock", "config.yaml");
};

export const validate = (cfg: KubeTarget): Effect.Effect<KubeTarget, ConfigInvalidError> => {
  if (!cfg.context) return Effect.fail(new ConfigInvalidError({ cause: "context is required" }));
  if (!cfg.namespace) return Effect.fail(new ConfigInvalidError({ cause: "namespace is required" }));
  if (cfg.namespace.length > 63 || !namespaceRe.test(cfg.namespace)) {
    return Effect.fail(
      new ConfigInvalidError({ cause: `namespace "${cfg.namespace}" must be a DNS-1123 label` }),
    );
  }
  return Effect.succeed(cfg);
};

export const load = (file: string): Effect.Effect<KubeTarget, ConfigError, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const data = yield* fs.readFileString(file).pipe(
      Effect.mapError((e) => new ConfigIOError({ cause: `read kubeflock config "${file}": ${String(e)}` })),
    );
    const parsed = yield* Effect.try({
      try: () => parse(data) as Partial<KubeTarget>,
      catch: (e) => new ConfigParseError({ cause: `parse kubeflock config "${file}": ${(e as Error).message}` }),
    });
    const cfg: KubeTarget = { context: parsed.context ?? "", namespace: parsed.namespace ?? "" };
    return yield* validate(cfg).pipe(
      Effect.mapError((e) => new ConfigInvalidError({ cause: `invalid kubeflock config "${file}": ${e.cause}` })),
    );
  });

export const save = (file: string, cfg: KubeTarget): Effect.Effect<void, ConfigError, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    yield* validate(cfg);
    const fs = yield* FileSystem.FileSystem;
    yield* fs.makeDirectory(Path.dirname(file), { recursive: true }).pipe(
      Effect.mapError((e) => new ConfigIOError({ cause: `create config dir: ${String(e)}` })),
    );
    yield* fs.writeFileString(file, stringify(cfg)).pipe(
      Effect.mapError((e) => new ConfigIOError({ cause: `write kubeflock config "${file}": ${String(e)}` })),
    );
    yield* Effect.tryPromise({
      try: () => import("node:fs/promises").then((m) => m.chmod(file, 0o600)),
      catch: (e) => new ConfigIOError({ cause: `chmod kubeflock config "${file}": ${(e as Error).message}` }),
    });
  });
