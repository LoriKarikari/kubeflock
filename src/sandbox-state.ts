import { FileSystem } from "@effect/platform";
import { Effect, Schema } from "effect";
import * as Path from "node:path";

const targetSchema = Schema.Struct({
  context: Schema.String,
  namespace: Schema.String,
  name: Schema.String,
  uid: Schema.String,
});

const baseSchema = {
  version: Schema.Literal(1),
  claim: targetSchema,
  template: Schema.String,
  warmPool: Schema.String,
  identityFile: Schema.String,
};

const managedSandboxSchema = Schema.Union(
  Schema.Struct({ ...baseSchema, phase: Schema.Literal("claimed") }),
  Schema.Struct({
    ...baseSchema,
    phase: Schema.Literal("bound"),
    sandbox: targetSchema,
    home: Schema.Struct({
      name: Schema.String,
      uid: Schema.String,
      capacity: Schema.String,
      storageClass: Schema.String,
    }),
  }),
);

export type ManagedSandbox = Schema.Schema.Type<typeof managedSandboxSchema>;
export type BoundSandbox = Extract<ManagedSandbox, { readonly phase: "bound" }>;

export const managedSandboxDir = (stateDir: string): string => Path.join(stateDir, "sandboxes");
export const managedSandboxPath = (stateDir: string, uid: string): string =>
  Path.join(managedSandboxDir(stateDir), `${uid}.json`);

export const listManagedSandboxes = (
  stateDir: string,
): Effect.Effect<ReadonlyArray<{ file: string; sandbox: ManagedSandbox }>, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const dir = managedSandboxDir(stateDir);
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
        return fs.readFileString(file).pipe(
          Effect.flatMap(Schema.decodeUnknown(Schema.parseJson(managedSandboxSchema))),
          Effect.map((sandbox) => ({ file, sandbox })),
        );
      },
      { concurrency: "unbounded" },
    );
  });

export const saveManagedSandbox = (
  stateDir: string,
  sandbox: ManagedSandbox,
): Effect.Effect<void, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const file = managedSandboxPath(stateDir, sandbox.claim.uid);
    yield* fs.makeDirectory(Path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${process.pid}.tmp`;
    yield* fs.writeFileString(temp, `${JSON.stringify(sandbox, null, 2)}\n`, { mode: 0o600 });
    yield* fs.rename(temp, file);
    yield* fs.chmod(file, 0o600);
  });
