import { Schema } from "effect";
import { mkdir, readFile, readdir, rename, chmod, writeFile } from "node:fs/promises";
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

export const loadConnection = async (file: string): Promise<Connection> => {
  const raw: unknown = JSON.parse(await readFile(file, "utf8"));
  return Schema.decodeUnknownSync(connectionSchema)(raw);
};

export const listConnections = async (dir: string): Promise<ReadonlyArray<{ file: string; connection: Connection }>> => {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
  return Promise.all(
    names.filter((name) => name.endsWith(".json")).sort((left, right) => left.localeCompare(right)).map(async (name) => {
      const file = Path.join(dir, name);
      return { file, connection: await loadConnection(file) };
    }),
  );
};

export const saveConnection = async (file: string, connection: Connection): Promise<void> => {
  await mkdir(Path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(connection, null, 2)}\n`, { mode: 0o600 });
  await rename(temp, file);
  await chmod(file, 0o600);
};
