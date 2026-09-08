import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parse } from "yaml";

const cli = fileURLToPath(new URL("../dist/Cli.js", import.meta.url));
let dir: string;
let config: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "kubeflock-cli-"));
  config = join(dir, "config.yaml");
  writeFileSync(config, "context: saved\nnamespace: dev\n");
});

afterEach(() => rmSync(dir, { recursive: true, force: true }));

const invoke = (args: ReadonlyArray<string>, entry = cli) =>
  spawnSync(process.execPath, [entry, ...args], {
    encoding: "utf8",
    timeout: 5000,
    env: { ...process.env, KUBEFLOCK_CONFIG: config },
  });

const fakeKubectl = (): string => {
  const file = join(dir, "kubectl");
  writeFileSync(file, '#!/bin/sh\n[ "$*" = "config get-contexts -o name" ] || exit 17\nprintf "saved\\n"\n', { mode: 0o755 });
  return file;
};

describe("built CLI", () => {
  it("shows the saved target as JSON through the linked entry", () => {
    const entry = join(dir, "kubeflock");
    symlinkSync(cli, entry);
    const result = invoke(["cluster", "config", "show", "--output=json"], entry);
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ context: "saved", namespace: "dev", config });
  });

  it("saves a target only after checking the context", () => {
    const result = invoke(["cluster", "config", "--context", "saved", "--namespace", "other", "--kubectl", fakeKubectl()]);
    expect(result.status).toBe(0);
    expect(parse(readFileSync(config, "utf8"))).toEqual({ context: "saved", namespace: "other" });
    expect(statSync(config).mode & 0o777).toBe(0o600);
  });

  it("preserves the saved target when the requested context does not exist", () => {
    const before = readFileSync(config, "utf8");
    const result = invoke(["cluster", "config", "--context", "missing", "--namespace", "other", "--kubectl", fakeKubectl()]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('context "missing" not found');
    expect(readFileSync(config, "utf8")).toBe(before);
  });

  it.each([
    ["empty", "", "invalid kubeflock config"],
    ["invalid YAML", "context: [saved", "parse kubeflock config"],
  ])("reports %s config without a runtime crash", (_name, body, message) => {
    writeFileSync(config, body);
    const result = invoke(["cluster", "config", "show"]);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain(message);
    expect(result.stderr).not.toContain("TypeError");
  });

  it("reports a missing config file", () => {
    rmSync(config);
    const result = invoke(["cluster", "check"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("read kubeflock config");
  });
});
