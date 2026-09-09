import { afterAll, beforeAll, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const root = join(import.meta.dirname, "..");
const cli = join(root, "dist", "cli.js");
const dir = mkdtempSync(join(tmpdir(), "kubeflock-connection-"));
const stateDir = join(dir, "state");
const config = join(dir, "config.yaml");
const kubeconfig = join(dir, "kubeconfig.yaml");
const sshConfig = join(dir, "ssh", "config");
const identity = join(dir, "id_ed25519");
const herdrState = join(dir, "herdr.json");
const uidFile = join(dir, "uid");
const kubectl = join(dir, "kubectl");
const kubectlLog = join(dir, "kubectl.log");
const herdr = join(dir, "herdr");
const credential = join(dir, "credential");
const keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
interface ClaimFixture {
  metadata: { name: string; namespace: string; uid: string; labels: { readonly [key: string]: string } };
  spec: { warmPoolRef: { name: string } };
  status?: {
    conditions: ReadonlyArray<{ type: string; status: string; reason?: string; message?: string }>;
    sandbox?: { name: string };
  };
}

let server: Server;
let claims = new Map<string, ClaimFixture>();
let claimCreates = 0;
let claimRequests: string[] = [];
let claimReads = new Map<string, number>();
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
  }, 10_000);
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
  FAKE_KUBECTL_LOG: kubectlLog,
});

const metadata = (name: string, uid = `${name}-uid`) => ({ name, namespace: "dev", uid });

const templateFixture = (name: string, secure: boolean) => ({
  metadata: metadata(name),
  spec: {
    networkPolicyManagement: "Managed",
    podTemplate: { spec: {
      runtimeClassName: secure ? "gvisor" : "runc",
      automountServiceAccountToken: false,
      securityContext: {
        runAsNonRoot: true,
        runAsUser: 1000,
        runAsGroup: 1000,
        fsGroup: 1000,
        seccompProfile: { type: "RuntimeDefault" },
      },
      containers: [{
        securityContext: {
          allowPrivilegeEscalation: false,
          runAsNonRoot: true,
          runAsUser: 1000,
          capabilities: { drop: ["ALL"] },
          seccompProfile: { type: "RuntimeDefault" },
        },
        ports: [{ name: "ssh", containerPort: 2200 }],
        resources: { requests: { cpu: "500m", memory: "1Gi" }, limits: { cpu: "2", memory: "4Gi" } },
        volumeMounts: [{ name: "home", mountPath: "/home/agent" }],
      }],
      volumes: [{ name: "home", persistentVolumeClaim: { claimName: "home" } }],
    } },
    volumeClaimTemplates: [{
      metadata: { name: "home" },
      spec: { storageClassName: "longhorn", resources: { requests: { storage: "10Gi" } } },
    }],
  },
});

const poolFixture = (template: string) => ({
  metadata: metadata(`${template}-pool`),
  spec: { replicas: 0, sandboxTemplateRef: { name: template } },
});

const claimFixture = (
  name: string,
  warmPool: string,
  labels: { readonly [key: string]: string } = { "app.kubernetes.io/managed-by": "kubeflock" },
): ClaimFixture => ({
  metadata: { ...metadata(name, `claim-${name}`), labels },
  spec: { warmPoolRef: { name: warmPool } },
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
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_KUBECTL_LOG, args.join(" ") + "\\n");
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
  const id = state.addCount.toString(16).padStart(32, "0");
  state.machines.push({ id, label: args[args.indexOf("--label") + 1], target: args[2], session: args[args.indexOf("--remote-session") + 1], enabled: true, selected: false });
  save();
} else if (args[0] === "machine" && (args[1] === "enable" || args[1] === "disable")) {
  const machine = state.machines.find((item) => item.id === args[2]);
  if (!machine) process.exit(1);
  machine.enabled = args[1] === "enable";
  save();
} else if (args.join(" ").startsWith("plugin pane open ")) {
  state.paneArgs = args;
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
    const url = new URL(request.url ?? "/", "http://fixture");
    const templateMatch = /\/sandboxtemplates\/([^/]+)$/.exec(url.pathname);
    if (templateMatch) {
      const secure = templateMatch[1] !== "insecure";
      response.end(JSON.stringify(templateFixture(templateMatch[1]!, secure)));
      return;
    }
    if (url.pathname.endsWith("/sandboxwarmpools")) {
      response.end(JSON.stringify({ items: [poolFixture("dev-small"), poolFixture("insecure")] }));
      return;
    }
    if (url.pathname.endsWith("/sandboxclaims") && request.method === "POST") {
      let body = "";
      request.setEncoding("utf8").on("data", (chunk: string) => { body += chunk; });
      request.on("end", () => {
        claimRequests.push(body);
        const submitted = JSON.parse(body);
        const name = submitted.metadata.name;
        if (claims.has(name)) {
          response.statusCode = 409;
          response.end(JSON.stringify({ message: "already exists" }));
          return;
        }
        claimCreates++;
        const claim = claimFixture(name, submitted.spec.warmPoolRef.name);
        if (name !== "delayed") claim.status = { conditions: [{ type: "Ready", status: "True" }], sandbox: { name } };
        claims.set(name, claim);
        response.statusCode = 201;
        response.end(JSON.stringify(claim));
      });
      return;
    }
    if (url.pathname.endsWith("/sandboxclaims")) {
      const field = url.searchParams.get("fieldSelector");
      if (field) {
        const name = field.slice("metadata.name=".length);
        const claim = claims.get(name);
        if (claim) {
          const reads = (claimReads.get(name) ?? 0) + 1;
          claimReads.set(name, reads);
          if (name === "delayed" && reads >= 2) claim.status = { conditions: [{ type: "Ready", status: "True" }], sandbox: { name } };
        }
        response.end(JSON.stringify({ items: claim ? [claim] : [] }));
      } else response.end(JSON.stringify({ items: [...claims.values()] }));
      return;
    }
    const sandboxMatch = /\/sandboxes\/([^/]+)$/.exec(url.pathname);
    if (sandboxMatch) {
      const name = sandboxMatch[1]!;
      const uid = name === "demo" ? readFileSync(uidFile, "utf8") : `sandbox-${name}`;
      response.end(JSON.stringify({
        metadata: { name, namespace: "dev", uid },
        status: { selector: `agents.x-k8s.io/sandbox=${name}`, conditions: [{ type: "Ready", status: "True" }] },
      }));
      return;
    }
    const pvcMatch = /\/persistentvolumeclaims\/home-([^/]+)$/.exec(url.pathname);
    if (pvcMatch) {
      const name = pvcMatch[1]!;
      response.end(JSON.stringify({
        metadata: { name: `home-${name}`, namespace: "dev", uid: `home-${name}-uid`, ownerReferences: [{ uid: `sandbox-${name}`, controller: true }] },
        spec: { storageClassName: "longhorn" },
        status: { capacity: { storage: "10Gi" } },
      }));
      return;
    }
    if (url.pathname.endsWith("/pods")) {
      const selector = url.searchParams.get("labelSelector") ?? "";
      const name = selector.slice("agents.x-k8s.io/sandbox=".length);
      const uid = name === "demo" ? readFileSync(uidFile, "utf8") : `sandbox-${name}`;
      response.end(JSON.stringify({ items: [{
        metadata: { name, ownerReferences: [{ uid, controller: true }] },
        spec: { containers: [{ name: "sandbox", ports: [{ name: "ssh", containerPort: 2200 }] }] },
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
  expect(manifest).toContain('command = ["node", "dist/cli.js", "sandbox", "disconnect"]');
  expect(manifest).toContain('command = ["node", "dist/cli.js", "sandbox", "reconnect"]');
  expect(manifest).toContain('command = ["node", "dist/cli.js", "sandbox", "create-action"]');
  expect(manifest).toContain('command = ["node", "dist/cli.js", "sandbox", "create-wizard"]');
  expect((await invoke(["sandbox", "create-action"], { HERDR_PLUGIN_ID: "kubeflock", HERDR_WORKSPACE_ID: "workspace-1" })).status).toBe(0);
  expect(JSON.parse(readFileSync(herdrState, "utf8")).paneArgs).toEqual([
    "plugin", "pane", "open", "--plugin", "kubeflock", "--entrypoint", "create", "--focus", "--workspace", "workspace-1",
  ]);
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
  expect(readFileSync(kubectlLog, "utf8")).toContain("TCP:127.0.0.1:2200");

  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig], { FAKE_HOST_KEY: keyB })).stderr).toContain("host key mismatch");
  writeFileSync(uidFile, "uid-2");
  expect((await invoke(["sandbox", "reconnect", "--kubeconfig", kubeconfig])).stderr).toContain("was replaced");
  const finalHerdrState = JSON.parse(readFileSync(herdrState, "utf8"));
  expect(finalHerdrState.machines.find((machine: { id: string }) => machine.id.startsWith("f"))).toMatchObject({ enabled: true });
  expect(new Set(apiMethods)).toEqual(new Set(["GET"]));
  expect(new Set(apiAuth)).toEqual(new Set(["Bearer fixture"]));
}, 30_000);

it("creates one hardened persistent sandbox, waits for readiness, and reports lifecycle state", async () => {
  claims = new Map();
  claimCreates = 0;
  claimRequests = [];
  claimReads = new Map();
  writeFileSync(uidFile, "uid-1");
  const beforeAdds = JSON.parse(readFileSync(herdrState, "utf8")).addCount;
  const created = await invoke([
    "sandbox", "create", "delayed", "--template", "dev-small", "--identity", identity,
    "--timeout", "10s", "--kubeconfig", kubeconfig,
  ]);
  expect(created.status).toBe(0);
  expect(created.stdout).toContain("ready sandbox delayed from dev-small");
  expect(claimReads.get("delayed")).toBe(2);
  expect(claimCreates).toBe(1);
  expect(JSON.parse(claimRequests[0]!)).toEqual({
    apiVersion: "extensions.agents.x-k8s.io/v1beta1",
    kind: "SandboxClaim",
    metadata: {
      name: "delayed",
      namespace: "dev",
      labels: { "app.kubernetes.io/managed-by": "kubeflock" },
    },
    spec: { warmPoolRef: { name: "dev-small-pool" } },
  });

  const saved = JSON.parse(readFileSync(join(stateDir, "sandboxes", "claim-delayed.json"), "utf8"));
  expect(saved).toMatchObject({
    phase: "bound",
    claim: { uid: "claim-delayed" },
    sandbox: { uid: "sandbox-delayed" },
    home: { uid: "home-delayed-uid", capacity: "10Gi", storageClass: "longhorn" },
  });
  const duplicate = await invoke([
    "sandbox", "create", "delayed", "--template", "dev-small", "--identity", identity,
    "--timeout", "2s", "--kubeconfig", kubeconfig,
  ]);
  expect(duplicate.status).toBe(0);
  expect(claimCreates).toBe(1);
  expect(JSON.parse(readFileSync(herdrState, "utf8")).addCount).toBe(beforeAdds + 1);

  const listed = await invoke(["sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig]);
  expect(JSON.parse(listed.stdout)).toContainEqual(expect.objectContaining({ name: "delayed", state: "ready" }));
  expect((await invoke(["sandbox", "disconnect", "delayed"])).status).toBe(0);
  const disconnected = await invoke(["sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig]);
  expect(JSON.parse(disconnected.stdout)).toContainEqual(expect.objectContaining({ name: "delayed", state: "disconnected" }));
}, 30_000);

it("fails safely across policy, quota, registration, replacement, and concurrent requests", async () => {
  const insecure = await invoke([
    "sandbox", "create", "unsafe", "--template", "insecure", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ]);
  expect(insecure).toMatchObject({ status: 2, stderr: expect.stringContaining("does not meet Kubeflock pod hardening requirements") });
  expect(claims.has("unsafe")).toBe(false);

  const quota = claimFixture("quota", "dev-small-pool");
  quota.status = {
    conditions: [{ type: "Ready", status: "False", reason: "Unschedulable", message: "exceeded quota: requests.storage" }],
  };
  claims.set("quota", quota);
  const exhausted = await invoke([
    "sandbox", "create", "quota", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ]);
  expect(exhausted.stderr).toContain("failed during readiness: Unschedulable: exceeded quota");
  const quotaList = await invoke(["sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig]);
  expect(JSON.parse(quotaList.stdout)).toContainEqual(expect.objectContaining({ name: "quota", state: "failed", step: "readiness" }));

  claims.set("waiting", claimFixture("waiting", "dev-small-pool"));
  const waiting = await invoke([
    "sandbox", "create", "waiting", "--template", "dev-small", "--identity", identity,
    "--timeout", "100ms", "--kubeconfig", kubeconfig,
  ]);
  expect(waiting.stderr).toContain("timed out during readiness");
  const waitingList = await invoke(["sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig]);
  expect(JSON.parse(waitingList.stdout)).toContainEqual(expect.objectContaining({ name: "waiting", state: "provisioning", step: "readiness" }));

  const unrelated = claimFixture("taken", "dev-small-pool", {});
  claims.set("taken", unrelated);
  const collision = await invoke([
    "sandbox", "create", "taken", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ]);
  expect(collision.stderr).toContain("is not managed by Kubeflock");

  const partial = await invoke([
    "sandbox", "create", "partial", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ], { FAKE_HERDR_FAIL_ADD: "1" });
  expect(partial.stderr).toContain("herdr exited");
  expect(JSON.parse(readFileSync(join(stateDir, "sandbox-partial.json"), "utf8")).phase).toBe("prepared");
  const partialList = await invoke(["sandbox", "list", "--output", "json", "--kubeconfig", kubeconfig]);
  expect(JSON.parse(partialList.stdout)).toContainEqual(expect.objectContaining({ name: "partial", state: "failed", step: "connection" }));
  expect((await invoke([
    "sandbox", "create", "partial", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ])).status).toBe(0);

  const beforeRace = claimCreates;
  const raceArgs = [
    "sandbox", "create", "race", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ];
  const race = await Promise.all([invoke(raceArgs), invoke(raceArgs)]);
  expect(race.filter((result) => result.status === 0)).toHaveLength(1);
  expect(race.find((result) => result.status !== 0)?.stderr).toContain("is already being created");
  expect(claimCreates).toBe(beforeRace + 1);

  const savedClaim = claims.get("partial")!;
  savedClaim.metadata = { ...metadata("partial", "replacement-claim"), labels: { "app.kubernetes.io/managed-by": "kubeflock" } };
  const replaced = await invoke([
    "sandbox", "create", "partial", "--template", "dev-small", "--identity", identity,
    "--kubeconfig", kubeconfig,
  ]);
  expect(replaced.stderr).toContain("was replaced");
}, 30_000);
