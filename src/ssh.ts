import { FileSystem } from "@effect/platform";
import { Effect } from "effect";
import * as Path from "node:path";
import type { Connection } from "./connection-state.js";

const atomicWrite = (file: string, data: string, mode: number): Effect.Effect<void, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    yield* fs.makeDirectory(Path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${process.pid}.tmp`;
    yield* fs.writeFileString(temp, data, { mode });
    yield* fs.rename(temp, file);
    yield* fs.chmod(file, mode);
  });

const escapedQuote = String.raw`\"`;
const sshQuote = (value: string): string => `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll('"', escapedQuote)}"`;
const shellQuote = (value: string): string => "'" + value.replaceAll("'", `'"'"'`) + "'";

export const normalizeHostKey = (raw: string): string => {
  const fields = raw.trim().split(/\s+/);
  if (fields.length < 2 || fields[0] !== "ssh-ed25519" || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1]!)) {
    throw new Error("sandbox returned an invalid Ed25519 host key");
  }
  return `${fields[0]} ${fields[1]}`;
};

export const ensureSshFiles = (
  connection: Connection,
  stateFile: string,
  nodePath: string,
  cliPath: string,
): Effect.Effect<void, Error, FileSystem.FileSystem> =>
  Effect.gen(function*() {
    const fs = yield* FileSystem.FileSystem;
    const ssh = connection.ssh;
    const exists = yield* fs.exists(ssh.configFile);
    const main = exists ? yield* fs.readFileString(ssh.configFile) : "";
    const mode = exists ? (yield* fs.stat(ssh.configFile)).mode & 0o777 : 0o600;
    const include = `Include ${sshQuote(ssh.entryFile)}`;
    const included = main.split("\n").some((line) => line.trim() === include || line.trim() === `Include ${ssh.entryFile}`);
    if (!included) yield* atomicWrite(ssh.configFile, `${include}\n${main}`, mode);

    yield* atomicWrite(ssh.knownHostsFile, `${ssh.alias} ${ssh.hostKey}\n`, 0o600);
    yield* atomicWrite(
      ssh.entryFile,
      `Host ${ssh.alias}\n  HostName ${ssh.alias}\n  User agent\n  IdentityFile ${sshQuote(ssh.identityFile)}\n  UserKnownHostsFile ${sshQuote(ssh.knownHostsFile)}\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  ProxyCommand ${sshQuote(ssh.proxyFile)}\n`,
      0o600,
    );
    yield* atomicWrite(
      ssh.proxyFile,
      `#!/bin/sh\nexec ${shellQuote(nodePath)} ${shellQuote(cliPath)} sandbox proxy --state ${shellQuote(stateFile)}\n`,
      0o700,
    );
  });
