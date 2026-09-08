import { describe, expect, it } from "vitest";
import { sanitizeLines } from "./Sanitize.js";

describe("sanitize", () => {
  it("redacts tokens, codes, and JWTs", () => {
    const input = [
      "Bearer abc.def.ghi token",
      "access_token=secret123",
      "login https://example.com/authorize?code=supersecret&state=x",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-part-here",
    ].join("\n");
    const out = sanitizeLines(input);
    expect(out).not.toContain("supersecret");
    expect(out).not.toContain("secret123");
    expect(out).not.toContain("eyJhbGci");
    expect(out).toContain("[redacted]");
  });

  it("redacts quoted and JSON credential values", () => {
    const quoted = 'access_token="TEST_ONLY_TOKEN"';
    expect(sanitizeLines(quoted)).not.toContain("TEST_ONLY_TOKEN");
    expect(sanitizeLines(quoted)).toContain("[redacted]");
    const json = '{"refresh_token": "TEST_JSON_TOKEN"}';
    expect(sanitizeLines(json)).not.toContain("TEST_JSON_TOKEN");
    expect(sanitizeLines(json)).toContain("[redacted]");
    const code = '{"code": "AUTH_CODE_XYZ"}';
    expect(sanitizeLines(code)).not.toContain("AUTH_CODE_XYZ");
  });
});
