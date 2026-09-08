export type Category =
  | "missing-infrastructure"
  | "denied"
  | "expired-authentication"
  | "connectivity"
  | "configuration"
  | "timeout"
  | "unknown";

const reConn =
  /connection refused|no such host|dial tcp|i\/o timeout|context deadline exceeded|unable to connect|network (is )?unreachable|tls handshake (timeout|failure)|temporary failure in name resolution|no route to host|connection (timed out|reset)/i;
const reAuth =
  /unauthorized|invalid bearer token|id token (has )?expired|token (has )?expired|reauthentication required|reauth|login required|interactive.*auth|authorization (code|url)|invalid_grant|unknown user|no auth provider|exec credential.*(fail|error).*auth|oidc.*expir/i;
const reDeny = /forbidden|cannot (get|list|create|watch|delete|patch|update).*forbidden|is forbidden:|User .* cannot/i;
const reMiss =
  /not found|NotFound|the server doesn'?t have a resource type|no matches for kind|resource mapping not found|could not find the requested resource|not served|no resources found|not installed/i;
const reCfg =
  /unknown flag|no context|context .* not found|context .* doesn'?t exist|invalid configuration|no server found|specifying a namespace|required flag/i;

export const classify = (stderr: string, timedOut: boolean): Category => {
  if (timedOut) {
    if (reConn.test(stderr)) return "connectivity";
    if (reAuth.test(stderr)) return "expired-authentication";
    return "timeout";
  }
  const s = stderr.trim();
  if (!s) return "unknown";
  if (reDeny.test(s)) return "denied";
  if (reAuth.test(s)) return "expired-authentication";
  if (reConn.test(s)) return "connectivity";
  if (reCfg.test(s)) return "configuration";
  if (reMiss.test(s)) return "missing-infrastructure";
  return "unknown";
};

export const remediation = (cat: Category): string => {
  switch (cat) {
    case "missing-infrastructure":
      return "Install the missing component or CRDs, then rerun this check. For Kubeflock installs this usually means the Helm chart or the Agent Sandbox controller.";
    case "denied":
      return "Access was denied by RBAC. Ask an administrator for the listed permissions in the configured namespace, then rerun this check.";
    case "expired-authentication":
      return "Authentication expired or needs renewal. Complete login in a terminal (for example with your OIDC helper), then rerun this check. Do not paste tokens or codes into logs.";
    case "connectivity":
      return "The API server could not be reached. Check network, VPN, and cluster power, then rerun this check.";
    case "timeout":
      return "The check timed out, possibly while a credential helper waited on a lock. Clear any stuck login helper, then rerun with a longer --timeout.";
    case "configuration":
      return "The saved context or kubeconfig is wrong. Run: kubeflock cluster config --context NAME --namespace NAME";
    default:
      return "Rerun with --output json for detail, fix the reported item, then rerun this check.";
  }
};
