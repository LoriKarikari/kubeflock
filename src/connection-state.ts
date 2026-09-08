import { FileSystem } from "@effect/platform";
import { Effect, Schema } from "effect";
import * as Os from "node:os";
import * as Path from "node:path";

const identitySchema = Schema.Struct({
  context: Schema.String,
  namespace: Schema.String,
  name: Schema.String,
  uid: Schema.String,
});

const sshSchema = Schema.Struct({
  alias: Schema.String,
  identityFile: Schema.String,
  knownHostsFile: Schema.String,
  entryFile: Schema.String,
  proxyFile: Schema.String,
  configFile: Schema.String,
  hostKey: Schema.String,
});

const baseSchema = {
  version: Schema.Literal(1),
  sandbox: identitySchema,
  ssh: sshSchema,
  herdr: Schema.Struct({ label: Schema.String, session: Schema.String }),
  kubeconfig: Schema.NullOr(Schema.String),
  kubectl: Schema.String,
};

const connectionSchema = Schema.Union(
  Schema.Struct({ ...baseSchema, phase: Schema.Literal("prepared") }),
  Schema.Struct({ ...baseSchema, phase: Schema.Literal("connected"), profileId: Schema.String }),
);

export type SandboxIdentity = Schema.Schema.Type<typeof identitySchema>;
export type Connection = Schema.Schema.Type<typeof connectionSchema>;
export type PreparedConnection = Extract<Connection, { readonly phase: "prepared" }>;

export const defaultStateDir = (): string => {
  const base = process.env["XDG_STATE_HOME"] ?? Path.join(Os.homedir(), ".local", "state");
  return Path.join(base, "kubeflock", "connections");
};

export const connectionPath = (dir: string, uid: string): string => Path.join(dir, `${uid}.json`);

export const loadConnection = (file: string): Effect.Effect<Connection, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const raw = yield* fs.readFileString(file);
    return yield* Schema.decodeUnknown(Schema.parseJson(connectionSchema))(raw);
  });

export const listConnections = (
  dir: string,
): Effect.Effect<ReadonlyArray<{ file: string; connection: Connection }>, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const names = yield* fs.readDirectory(dir).pipe(
      Effect.catchIf(
        (error) => error._tag === "SystemError" && error.reason === "NotFound",
        () => Effect.succeed([]),
      ),
    );
    return yield* Effect.forEach(
      names.filter((name) => name.endsWith(".json")).sort((left, right) => left.localeCompare(right)),
      (name) => {
        const file = Path.join(dir, name);
        return loadConnection(file).pipe(Effect.map((connection) => ({ file, connection })));
      },
      { concurrency: "unbounded" },
    );
  });

export const saveConnection = (
  file: string,
  connection: Connection,
): Effect.Effect<void, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    yield* fs.makeDirectory(Path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${process.pid}.tmp`;
    yield* fs.writeFileString(temp, `${JSON.stringify(connection, null, 2)}\n`, { mode: 0o600 });
    yield* fs.rename(temp, file);
    yield* fs.chmod(file, 0o600);
  });
