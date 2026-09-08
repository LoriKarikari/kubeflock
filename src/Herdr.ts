import { spawn } from "node:child_process";
import { Schema } from "effect";
import type { Connection } from "./ConnectionState.js";

const machineSchema = Schema.Array(Schema.Struct({
  id: Schema.String,
  label: Schema.String,
  target: Schema.String,
  session: Schema.String,
  enabled: Schema.Boolean,
  selected: Schema.Boolean,
}));
export type HerdrMachine = Schema.Schema.Type<typeof machineSchema>[number];

const binary = (): string => process.env["KUBEFLOCK_HERDR"] ?? "herdr";

const run = (args: ReadonlyArray<string>, inherit = false): Promise<string> => new Promise((resolve, reject) => {
  const child = spawn(binary(), [...args], { stdio: inherit ? "inherit" : ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  if (!inherit) {
    child.stdout?.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    child.stderr?.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
  }
  child.once("error", reject);
  child.once("close", (code) => {
    if (code === 0) resolve(stdout);
    else reject(new Error(stderr.trim() || `herdr exited with status ${code ?? "unknown"}`));
  });
});

export const listMachines = async (): Promise<ReadonlyArray<HerdrMachine>> => {
  const raw: unknown = JSON.parse(await run(["machine", "list", "--json"]));
  return Schema.decodeUnknownSync(machineSchema)(raw);
};

const owned = (machine: HerdrMachine, connection: Connection): boolean =>
  machine.label === connection.herdr.label &&
  machine.target === connection.ssh.alias &&
  machine.session === connection.herdr.session;

export const ensureMachine = async (connection: Connection): Promise<string> => {
  let machines = await listMachines();
  if (connection.phase === "connected") {
    const machine = machines.find((candidate) => candidate.id === connection.profileId);
    if (!machine || !owned(machine, connection)) {
      throw new Error(`Kubeflock Herdr profile ${connection.profileId} is missing or no longer matches its saved identity`);
    }
    if (!machine.enabled) await run(["machine", "enable", machine.id]);
    return machine.id;
  }
  let matches = machines.filter((machine) => owned(machine, connection));
  if (matches.length > 1) throw new Error(`multiple Herdr profiles match ${connection.ssh.alias}`);
  if (matches.length === 0) {
    await run([
      "machine", "add", connection.ssh.alias,
      "--label", connection.herdr.label,
      "--remote-session", connection.herdr.session,
    ], true);
    machines = await listMachines();
    matches = machines.filter((machine) => owned(machine, connection));
  }
  const machine = matches[0];
  if (!machine || matches.length !== 1) throw new Error("Herdr reported success but did not save the Kubeflock machine profile");
  if (!machine.enabled) await run(["machine", "enable", machine.id]);
  return machine.id;
};

export const disableMachine = async (connection: Extract<Connection, { readonly phase: "connected" }>): Promise<void> => {
  const machine = (await listMachines()).find((candidate) => candidate.id === connection.profileId);
  if (!machine) return;
  if (!owned(machine, connection)) throw new Error(`refusing to disable non-Kubeflock profile ${connection.profileId}`);
  if (machine.enabled) await run(["machine", "disable", machine.id]);
};
