package kubeflock

import (
	"regexp"
	"strings"
)

var redactions = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)bearer\s+[a-z0-9._~+/=-]+`), "bearer [redacted]"},
	{regexp.MustCompile(`(?i)((?:id|access|refresh)[_-]?token\s*[:=]\s*"?)[^"\s;,}]+`), "$1[redacted]"},
	{regexp.MustCompile(`(?i)(client[_-]?secret\s*[:=]\s*"?)[^"\s;,}]+`), "$1[redacted]"},
	{regexp.MustCompile(`(?i)((?:authorization|auth)[_-]?code\s*[:=]\s*"?)[^"\s;,}]+`), "$1[redacted]"},
	{regexp.MustCompile(`(?i)([?&](?:code|token|id_token|access_token|refresh_token)="?)[^"&\s;,}]+`), "$1[redacted]"},
	{regexp.MustCompile(`\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}`), "[redacted-jwt]"},
}

var jsonCredential = regexp.MustCompile(`(?i)("[^"]*(?:code|token|secret)[^"]*"\s*:\s*"?)[^"\s\],}]+`)

func sanitizeLines(value string) string {
	lines := strings.Split(value, "\n")
	out := lines[:0]
	for _, line := range lines {
		for _, redaction := range redactions {
			line = redaction.re.ReplaceAllString(line, redaction.replacement)
		}
		line = jsonCredential.ReplaceAllString(line, "$1[redacted]")
		low := strings.ToLower(line)
		if strings.Contains(low, "verification_url") && strings.Contains(low, "user_code") {
			continue
		}
		if strings.Contains(low, "authorize") && strings.Contains(low, "code=") && strings.Contains(low, "[redacted]") {
			out = append(out, "authorization URL omitted; complete login in a terminal")
			continue
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

var categories = []struct {
	name string
	re   *regexp.Regexp
}{
	{"denied", regexp.MustCompile(`(?i)forbidden|cannot (get|list|create|watch|delete|patch|update).*forbidden|is forbidden:|User .* cannot`)},
	{"expired-authentication", regexp.MustCompile(`(?i)unauthorized|invalid bearer token|id token (has )?expired|token (has )?expired|reauthentication required|reauth|login required|interactive.*auth|authorization (code|url)|invalid_grant|unknown user|no auth provider|exec credential.*(fail|error).*auth|oidc.*expir`)},
	{"connectivity", regexp.MustCompile(`(?i)connection refused|no such host|dial tcp|i/o timeout|context deadline exceeded|unable to connect|network (is )?unreachable|tls handshake (timeout|failure)|temporary failure in name resolution|no route to host|connection (timed out|reset)`)},
	{"configuration", regexp.MustCompile(`(?i)unknown flag|no context|context .* not found|context .* doesn't exist|invalid configuration|no server found|specifying a namespace|required flag`)},
	{"missing-infrastructure", regexp.MustCompile(`(?i)not found|NotFound|the server doesn't have a resource type|no matches for kind|resource mapping not found|could not find the requested resource|not served|no resources found|not installed`)},
}

func classify(stderr string, timedOut bool) string {
	if timedOut {
		for _, category := range categories[1:3] {
			if category.re.MatchString(stderr) {
				return category.name
			}
		}
		return "timeout"
	}
	if strings.TrimSpace(stderr) == "" {
		return "unknown"
	}
	for _, category := range categories {
		if category.re.MatchString(stderr) {
			return category.name
		}
	}
	return "unknown"
}

func remediation(category string) string {
	switch category {
	case "missing-infrastructure":
		return "Install the missing component or CRDs, then rerun this check. For Kubeflock installs this usually means the Helm chart or the Agent Sandbox controller."
	case "denied":
		return "Access was denied by RBAC. Ask an administrator for the listed permissions in the configured namespace, then rerun this check."
	case "expired-authentication":
		return "Authentication expired or needs renewal. Complete login in a terminal (for example with your OIDC helper), then rerun this check. Do not paste tokens or codes into logs."
	case "connectivity":
		return "The API server could not be reached. Check network, VPN, and cluster power, then rerun this check."
	case "timeout":
		return "The check timed out, possibly while a credential helper waited on a lock. Clear any stuck login helper, then rerun with a longer --timeout."
	case "configuration":
		return "The saved context or kubeconfig is wrong. Run: kubeflock cluster config --context NAME --namespace NAME"
	default:
		return "Rerun with --output json for detail, fix the reported item, then rerun this check."
	}
}
