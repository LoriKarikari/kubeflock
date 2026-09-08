import { describe, expect, it } from "vitest";
import { classify } from "./Classify.js";

describe("classify", () => {
  it.each([
    ["Error from server (Forbidden): sandboxes is forbidden", false, "denied"],
    ["Unauthorized: ID token expired", false, "expired-authentication"],
    ["Unable to connect to the server: dial tcp: connection refused", false, "connectivity"],
    [`error: context "x" not found`, false, "configuration"],
    [`runtimeclasses.node.k8s.io "gvisor" not found`, false, "missing-infrastructure"],
    ["", true, "timeout"],
    ["something strange", false, "unknown"],
  ] satisfies Array<[string, boolean, string]>)("classify %j", (stderr, timed, want) => {
    expect(classify(stderr, timed)).toBe(want);
  });
});
