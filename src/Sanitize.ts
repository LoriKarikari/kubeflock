// sanitize redacts credential-like values before output reaches users or
// Herdr logs. It errs toward redacting too much rather than leaking a token
// or authorization code.

const reBearer = /bearer\s+[A-Za-z0-9\-._~+/=]+/gi;
const reTokenAssign =
  /((?:id[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization[_-]?code|auth[_-]?code)\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reCodeParam = /([?&](?:code|token|id_token|access_token|refresh_token)="?)[^"&\s;,}]+/gi;
const reJsonCred = /("[^"]*(?:code|token|secret)"\s*:\s*"?)[^"\s\],}]+/gi;
const reJwt = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

const redactOne = (s: string): string =>
  s
    .replace(reBearer, "bearer [redacted]")
    .replace(reTokenAssign, "$1[redacted]")
    .replace(reCodeParam, "$1[redacted]")
    .replace(reJsonCred, "$1[redacted]")
    .replace(reJwt, "[redacted-jwt]");

export const sanitizeLines = (s: string): string => {
  const out: Array<string> = [];
  for (const line of s.split("\n")) {
    const r = redactOne(line);
    const low = r.toLowerCase();
    if (low.includes("verification_url") && low.includes("user_code")) continue;
    if (low.includes("authorize") && low.includes("code=") && low.includes("[redacted]")) {
      out.push("authorization URL omitted; complete login in a terminal");
      continue;
    }
    out.push(r);
  }
  return out.join("\n").replace(/^\n+|\n+$/g, "");
};
