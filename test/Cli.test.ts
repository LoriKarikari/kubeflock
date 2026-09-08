import { describe, expect, it } from "vitest";
import { parseDuration } from "../src/Cli.js";

describe("parseDuration", () => {
  it.each([
    ["60s", 60000],
    ["500ms", 500],
    ["2m", 120000],
    ["1h", 3600000],
    ["10", 10000],
  ] satisfies Array<[string, number]>)("parses %s", (raw, ms) => {
    expect(parseDuration(raw)).toBe(ms);
  });

  it("rejects garbage", () => {
    expect(() => parseDuration("soon")).toThrow('bad duration "soon"');
  });
});
