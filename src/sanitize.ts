const reBearer = /bearer\s+[a-z0-9._~+/=-]+/gi;
const reIdTokenAssign = /(id[_-]?token\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reAccessTokenAssign = /(access[_-]?token\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reRefreshTokenAssign = /(refresh[_-]?token\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reSecretAssign = /(client[_-]?secret\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reAuthCodeAssign = /((?:authorization|auth)[_-]?code\s*[:=]\s*"?)[^"\s;,}]+/gi;
const reCodeParam = /([?&](?:code|token)="?)[^"&\s;,}]+/gi;
const reTokenParam = /([?&](?:id_token|access_token|refresh_token)="?)[^"&\s;,}]+/gi;
const reJsonValue = /("[^"]+"\s*:\s*"?)[^"\s\],}]+/gi;
const credentialWords = ["code", "token", "secret"];
const reJwt = /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}/g;

const redactOne = (s: string): string =>
  s
    .replace(reBearer, "bearer [redacted]")
    .replace(reIdTokenAssign, "$1[redacted]")
    .replace(reAccessTokenAssign, "$1[redacted]")
    .replace(reRefreshTokenAssign, "$1[redacted]")
    .replace(reSecretAssign, "$1[redacted]")
    .replace(reAuthCodeAssign, "$1[redacted]")
    .replace(reCodeParam, "$1[redacted]")
    .replace(reTokenParam, "$1[redacted]")
    .replace(reJsonValue, (match, key: string) =>
      credentialWords.some((word) => key.toLowerCase().includes(word)) ? `${key}[redacted]` : match)
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
  return out.join("\n").trim();
};
