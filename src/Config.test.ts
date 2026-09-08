import { Effect } from "effect";
import { NodeFileSystem } from "@effect/platform-node";
import { mkdtempSync, rmSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as Path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPath, load, save, validate } from "./Config.js";

describe("config round trip", () => {
  it("saves and loads", async () => {
    const dir = mkdtempSync(Path.join(tmpdir(), "kf-config-"));
    try {
      const file = Path.join(dir, "kubeflock", "config.yaml");
      await Effect.runPromise(Effect.provide(save(file, { context: "homelab", namespace: "kubeflock-check" }), NodeFileSystem.layer));
      const got = await Effect.runPromise(Effect.provide(load(file), NodeFileSystem.layer));
      expect(got).toEqual({ context: "homelab", namespace: "kubeflock-check" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("load rejects malformed files", () => {
  it.each([
    ["empty file", ""],
    ["null document", "null\n"],
    ["numeric context", "context: 123\nnamespace: kubeflock-check\n"],
    ["numeric namespace", "context: homelab\nnamespace: 456\n"],
    ["array document", "- homelab\n"],
    ["string document", "just a string\n"],
  ])("%s", async (_label, body) => {
    const dir = mkdtempSync(Path.join(tmpdir(), "kf-config-"));
    try {
      const file = Path.join(dir, "config.yaml");
      await writeFile(file, body);
      const tag = await Effect.runPromise(
        Effect.match(Effect.provide(load(file), NodeFileSystem.layer), {
          onFailure: (e) => e._tag,
          onSuccess: () => "ok",
        }),
      );
      expect(tag).toBe("ConfigInvalidError");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
describe("validate", () => {
  it.each([
    [{ context: "a", namespace: "b" }, true],
    [{ context: "", namespace: "b" }, false],
    [{ context: "a", namespace: "" }, false],
    [{ context: "a", namespace: "Bad_NS" }, false],
    [{ context: "a", namespace: "UPPER" }, false],
  ])("validate %j -> %s", async (cfg, valid) => {
    const res = await Effect.runPromise(Effect.match(validate(cfg), {
      onFailure: () => false,
      onSuccess: () => true,
    }));
    expect(res).toBe(valid);
  });
});

describe("defaultPath", () => {
  it("prefers KUBEFLOCK_CONFIG", () => {
    const prev = process.env["KUBEFLOCK_CONFIG"];
    process.env["KUBEFLOCK_CONFIG"] = "/tmp/custom.yaml";
    try {
      expect(defaultPath()).toBe("/tmp/custom.yaml");
    } finally {
      if (prev === undefined) delete process.env["KUBEFLOCK_CONFIG"];
      else process.env["KUBEFLOCK_CONFIG"] = prev;
    }
  });

  it("falls back to XDG_CONFIG_HOME", () => {
    const prevCfg = process.env["KUBEFLOCK_CONFIG"];
    const prevXdg = process.env["XDG_CONFIG_HOME"];
    delete process.env["KUBEFLOCK_CONFIG"];
    process.env["XDG_CONFIG_HOME"] = "/tmp/xdg";
    try {
      expect(defaultPath()).toBe(Path.join("/tmp/xdg", "kubeflock", "config.yaml"));
    } finally {
      if (prevCfg !== undefined) process.env["KUBEFLOCK_CONFIG"] = prevCfg;
      if (prevXdg === undefined) delete process.env["XDG_CONFIG_HOME"];
      else process.env["XDG_CONFIG_HOME"] = prevXdg;
    }
  });
});
