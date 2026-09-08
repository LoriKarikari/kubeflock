import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import * as Path from "node:path";
import type { Connection } from "./ConnectionState.js";

const atomicWrite = async (file: string, data: string, mode: number): Promise<void> => {
  await mkdir(Path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  await writeFile(temp, data, { mode });
  await rename(temp, file);
  await chmod(file, mode);
};

const sshQuote = (value: string): string => `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
const shellQuote = (value: string): string => `'${value.replaceAll("'", `'"'"'`)}'`;

export const normalizeHostKey = (raw: string): string => {
  const fields = raw.trim().split(/\s+/);
  if (fields.length < 2 || fields[0] !== "ssh-ed25519" || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1]!)) {
    throw new Error("sandbox returned an invalid Ed25519 host key");
  }
  return `${fields[0]} ${fields[1]}`;
};

export const ensureSshFiles = async (
  connection: Connection,
  stateFile: string,
  nodePath: string,
  cliPath: string,
): Promise<void> => {
  const ssh = connection.ssh;
  let main = "";
  let mode = 0o600;
  try {
    main = await readFile(ssh.configFile, "utf8");
    mode = (await stat(ssh.configFile)).mode & 0o777;
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  }
  const include = `Include ${sshQuote(ssh.entryFile)}`;
  const included = main.split("\n").some((line) => line.trim() === include || line.trim() === `Include ${ssh.entryFile}`);
  if (!included) await atomicWrite(ssh.configFile, `${include}\n${main}`, mode);

  await atomicWrite(ssh.knownHostsFile, `${ssh.alias} ${ssh.hostKey}\n`, 0o600);
  await atomicWrite(
    ssh.entryFile,
    `Host ${ssh.alias}\n  HostName ${ssh.alias}\n  User agent\n  IdentityFile ${sshQuote(ssh.identityFile)}\n  UserKnownHostsFile ${sshQuote(ssh.knownHostsFile)}\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  ProxyCommand ${sshQuote(ssh.proxyFile)}\n`,
    0o600,
  );
  await atomicWrite(
    ssh.proxyFile,
    `#!/bin/sh\nexec ${shellQuote(nodePath)} ${shellQuote(cliPath)} sandbox proxy --state ${shellQuote(stateFile)}\n`,
    0o700,
  );
};
