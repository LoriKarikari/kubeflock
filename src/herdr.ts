import { spawn } from "node:child_process";
import { Effect, Schema } from "effect";
import type { Connection } from "./connection-state.js";

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

const run = (args: ReadonlyArray<string>, inherit = false): Effect.Effect<string, Error> =>
  Effect.async((resume) => {
    let child;
    try {
      child = spawn(binary(), [...args], { stdio: inherit ? "inherit" : ["ignore", "pipe", "pipe"] });
    } catch (error) {
      resume(Effect.fail(error instanceof Error ? error : new Error("Herdr command failed")));
      return;
    }
    let stdout = "";
    let stderr = "";
    if (!inherit) {
      child.stdout?.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
      child.stderr?.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    }
    child.once("error", (error) => resume(Effect.fail(error)));
    child.once("close", (code) => resume(code === 0
      ? Effect.succeed(stdout)
      : Effect.fail(new Error(stderr.trim() || `herdr exited with status ${code ?? "unknown"}`))));
    return Effect.sync(() => child.kill());
  });

export const listMachines = (): Effect.Effect<ReadonlyArray<HerdrMachine>, Error> =>
  Effect.gen(function*() {
    const raw = yield* run(["machine", "list", "--json"]);
    return yield* Schema.decodeUnknown(Schema.parseJson(machineSchema))(raw);
  });

const owned = (machine: HerdrMachine, connection: Connection): boolean =>
  machine.label === connection.herdr.label &&
  machine.target === connection.ssh.alias &&
  machine.session === connection.herdr.session;

export const ensureMachine = (connection: Connection): Effect.Effect<string, Error> =>
  Effect.gen(function*() {
    let machines = yield* listMachines();
    if (connection.phase === "connected") {
      const machine = machines.find((candidate) => candidate.id === connection.profileId);
      if (!machine || !owned(machine, connection)) {
        return yield* Effect.fail(new Error(`Kubeflock Herdr profile ${connection.profileId} is missing or no longer matches its saved identity`));
      }
      if (!machine.enabled) yield* run(["machine", "enable", machine.id]);
      return machine.id;
    }
    let matches = machines.filter((machine) => owned(machine, connection));
    if (matches.length > 1) return yield* Effect.fail(new Error(`multiple Herdr profiles match ${connection.ssh.alias}`));
    if (matches.length === 0) {
      yield* run([
        "machine", "add", connection.ssh.alias,
        "--label", connection.herdr.label,
        "--remote-session", connection.herdr.session,
      ], true);
      machines = yield* listMachines();
      matches = machines.filter((machine) => owned(machine, connection));
    }
    const machine = matches[0];
    if (!machine || matches.length !== 1) {
      return yield* Effect.fail(new Error("Herdr reported success but did not save the Kubeflock machine profile"));
    }
    if (!machine.enabled) yield* run(["machine", "enable", machine.id]);
    return machine.id;
  });

export const disableMachine = (
  connection: Extract<Connection, { readonly phase: "connected" }>,
): Effect.Effect<void, Error> =>
  Effect.gen(function*() {
    const machine = (yield* listMachines()).find((candidate) => candidate.id === connection.profileId);
    if (!machine) return;
    if (!owned(machine, connection)) {
      return yield* Effect.fail(new Error(`refusing to disable non-Kubeflock profile ${connection.profileId}`));
    }
    if (machine.enabled) yield* run(["machine", "disable", machine.id]);
  });
