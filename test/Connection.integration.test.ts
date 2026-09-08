import { afterAll, beforeAll, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const root = join(import.meta.dirname, "..");
const cli = join(root, "dist", "Cli.js");
const dir = mkdtempSync(join(tmpdir(), "kubeflock-connection-"));
const stateDir = join(dir, "state");
const config = join(dir, "config.yaml");
const kubeconfig = join(dir, "kubeconfig.yaml");
const sshConfig = join(dir, "ssh", "config");
const identity = join(dir, "id_ed25519");
const herdrState = join(dir, "herdr.json");
const uidFile = join(dir, "uid");
const kubectl = join(dir, "kubectl");
const herdr = join(dir, "herdr");
const credential = join(dir, "credential");
const keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
let server: Server;
const apiMethods: string[] = [];
const apiAuth: string[] = [];

const run = (
  command: string,
  args: ReadonlyArray<string>,
  extra: NodeJS.ProcessEnv = {},
  input?: string,
): Promise<{ status: number | null; stdout: string; stderr: string }> => new Promise((resolve, reject) => {
  const child = spawn(command, [...args], { env: { ...process.env, ...baseEnv(), ...extra } });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
  const timeout = setTimeout(() => {
    child.kill("SIGKILL");
    reject(new Error(`timed out: ${command} ${args.join(" ")}`));
  }, 4_000);
  child.once("error", reject);
  child.once("close", (status) => {
    clearTimeout(timeout);
    resolve({ status, stdout, stderr });
  });
  child.stdin.end(input);
});

const invoke = (args: ReadonlyArray<string>, extra: NodeJS.ProcessEnv = {}) =>
  run(process.execPath, [cli, ...args], extra);

const baseEnv = (): NodeJS.ProcessEnv => ({
  KUBEFLOCK_CONFIG: config,
  KUBEFLOCK_STATE_DIR: stateDir,
  KUBEFLOCK_KUBECTL: kubectl,
  KUBEFLOCK_HERDR: herdr,
  KUBEFLOCK_SSH_CONFIG: sshConfig,
  FAKE_HERDR_STATE: herdrState,
  FAKE_HOST_KEY: keyA,
});

beforeAll(async () => {
  mkdirSync(join(dir, "ssh"), { recursive: true });
  writeFileSync(config, "context: test\nnamespace: dev\n");
  writeFileSync(identity, "private key fixture\n", { mode: 0o600 });
  writeFileSync(sshConfig, "Host unrelated\n  HostName unrelated.example\n");
  writeFileSync(uidFile, "uid-1");
  writeFileSync(herdrState, JSON.stringify({
    addCount: 0,
    selected: "local",
    machines: [{
      id: "ffffffffffffffffffffffffffffffff",
      label: "Unrelated",
      target: "unrelated",
      session: "main",
      enabled: true,
      selected: false,
    }],
  }));
  writeFileSync(kubectl, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.some((arg) => arg.endsWith("ssh_host_ed25519_key.pub"))) process.stdout.write(process.env.FAKE_HOST_KEY + "\\n");
else if (args.includes("socat")) process.stdin.pipe(process.stdout);
else process.exit(2);
`);
  writeFileSync(herdr, `#!/usr/bin/env node
const fs = require("node:fs");
const file = process.env.FAKE_HERDR_STATE;
const state = JSON.parse(fs.readFileSync(file, "utf8"));
const args = process.argv.slice(2);
const save = () => fs.writeFileSync(file, JSON.stringify(state));
if (args.join(" ") === "machine list --json") console.log(JSON.stringify(state.machines));
else if (args[0] === "machine" && args[1] === "add") {
  if (process.env.FAKE_HERDR_FAIL_ADD === "1") process.exit(1);
  state.addCount++;
  state.machines.push({ id: "0123456789abcdef0123456789abcdef", label: args[args.indexOf("--label") + 1], target: args[2], session: args[args.indexOf("--remote-session") + 1], enabled: true, selected: false });
  save();
} else if (args[0] === "machine" && (args[1] === "enable" || args[1] === "disable")) {
  const machine = state.machines.find((item) => item.id === args[2]);
  if (!machine) process.exit(1);
  machine.enabled = args[1] === "enable";
  save();
} else process.exit(2);
`);
  writeFileSync(credential, `#!/bin/sh
printf '%s\\n' '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"fixture"}}'
`);
  chmodSync(kubectl, 0o755);
  chmodSync(herdr, 0o755);
  chmodSync(credential, 0o755);

  server = createServer((request, response) => {
    apiMethods.push(request.method ?? "");
    apiAuth.push(request.headers.authorization ?? "");
    response.setHeader("content-type", "application/json");
    if (request.url?.includes("/sandboxes/demo")) {
      response.end(JSON.stringify({
        metadata: { name: "demo", namespace: "dev", uid: readFileSync(uidFile, "utf8") },
        status: { selector: "agents.x-k8s.io/sandbox=demo", conditions: [{ type: "Ready", status: "True" }] },
      }));
      return;
    }
    if (request.url?.startsWith("/api/v1/namespaces/dev/pods")) {
      response.end(JSON.stringify({ items: [{
        metadata: { name: "demo", ownerReferences: [{ uid: readFileSync(uidFile, "utf8"), controller: true }] },
        spec: { containers: [{ name: "sandbox" }] },
      }] }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ message: "not found" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || !(address instanceof Object) || !("port" in address)) throw new Error("test API server did not bind TCP");
  writeFileSync(kubeconfig, `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: http://127.0.0.1:${address.port}
    insecure-skip-tls-verify: true
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ${credential}
      env: null
      interactiveMode: Never
`);
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

it("reconciles connection failures, duplicate requests, Herdr actions, and replacement identity", async () => {
  const initial = await invoke([
    "sandbox", "connect", "demo", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ], { FAKE_HERDR_FAIL_ADD: "1" });
  expect(initial.status).toBe(2);
  expect(initial.stderr).toContain("herdr exited");
  const stateFile = join(stateDir, "uid-1.json");
  expect(JSON.parse(readFileSync(stateFile, "utf8")).phase).toBe("prepared");

  const connected = await invoke([
    "sandbox", "connect", "demo", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ]);
  expect(connected.status).toBe(0);
  expect(JSON.parse(readFileSync(stateFile, "utf8")).phase).toBe("connected");
  expect(JSON.parse(readFileSync(herdrState, "utf8")).addCount).toBe(1);
  expect(readFileSync(sshConfig, "utf8")).toContain("Include ");
  expect(readFileSync(sshConfig, "utf8")).toContain("Host unrelated\n  HostName unrelated.example\n");
  expect(readFileSync(join(dir, "state", "..", "ssh", "uid-1.conf"), "utf8")).toContain("StrictHostKeyChecking yes");
  const ssh = await run("ssh", ["-G", "-F", sshConfig, "kubeflock-uid-1"]);
  expect(ssh.status).toBe(0);
  expect(ssh.stdout).toContain("stricthostkeychecking true");
  expect(ssh.stdout).toContain("userknownhostsfile ");

  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig])).status).toBe(0);
  expect(JSON.parse(readFileSync(herdrState, "utf8")).addCount).toBe(1);

  const manifest = readFileSync(join(root, "herdr-plugin.toml"), "utf8");
  expect(manifest).toContain('command = ["node", "dist/Cli.js", "sandbox", "disconnect"]');
  expect(manifest).toContain('command = ["node", "dist/Cli.js", "sandbox", "reconnect"]');
  const sleeper = spawn("sleep", ["30"]);
  writeFileSync(config, "invalid: [");
  expect((await invoke(["sandbox", "disconnect"])).status).toBe(0);
  expect(sleeper.exitCode).toBeNull();
  expect(JSON.parse(readFileSync(herdrState, "utf8")).selected).toBe("local");
  writeFileSync(config, "context: test\nnamespace: dev\n");
  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig])).status).toBe(0);
  expect(sleeper.exitCode).toBeNull();
  sleeper.kill();

  const proxyFile = join(dir, "state", "..", "ssh", "uid-1-proxy");
  expect((await run(proxyFile, [], {}, "through-api")).stdout).toBe("through-api");

  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig], { FAKE_HOST_KEY: keyB })).stderr).toContain("host key mismatch");
  writeFileSync(uidFile, "uid-2");
  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig])).stderr).toContain("was replaced");
  const finalHerdrState = JSON.parse(readFileSync(herdrState, "utf8"));
  expect(finalHerdrState.machines.find((machine: { id: string }) => machine.id.startsWith("f"))).toMatchObject({ enabled: true });
  expect(new Set(apiMethods)).toEqual(new Set(["GET"]));
  expect(new Set(apiAuth)).toEqual(new Set(["Bearer fixture"]));
}, 30_000);
