package check

import (
	"regexp"
	"strings"
)

// Category distinguishes why a prerequisite failed so output can guide
// the next step without printing credentials.
type Category string

const (
	CategoryOK           Category = ""
	CategoryMissing      Category = "missing-infrastructure"
	CategoryDenied       Category = "denied"
	CategoryAuthExpired  Category = "expired-authentication"
	CategoryConnectivity Category = "connectivity"
	CategoryConfig       Category = "configuration"
	CategoryTimeout      Category = "timeout"
	CategoryUnknown      Category = "unknown"
)

var (
	reConn = regexp.MustCompile(`(?i)(connection refused|no such host|dial tcp|i/o timeout|context deadline exceeded|unable to connect|network (is )?unreachable|tls handshake (timeout|failure)|temporary failure in name resolution|no route to host|connection (timed out|reset))`)
	reAuth = regexp.MustCompile(`(?i)(unauthorized|invalid bearer token|id token (has )?expired|token (has )?expired|reauthentication required|reauth|login required|interactive.*auth|authorization (code|url)|invalid_grant|unknown user|no auth provider|exec credential.*(fail|error).*auth|oidc.*expir)`)
	reDeny = regexp.MustCompile(`(?i)(forbidden|cannot (get|list|create|watch|delete|patch|update).*forbidden|is forbidden:|User .* cannot)`)
	reMiss = regexp.MustCompile(`(?i)(not found|NotFound|the server doesn'?t have a resource type|no matches for kind|resource mapping not found|could not find the requested resource|not served|no resources found|not installed)`)
	reCfg  = regexp.MustCompile(`(?i)(unknown flag|no context|context .* not found|context .* doesn'?t exist|invalid configuration|no server found|specifying a namespace|required flag)`)
)

// Classify maps kubectl stderr/output to a failure category.
func Classify(stderr string, timedOut bool) Category {
	if timedOut {
		if reConn.MatchString(stderr) {
			return CategoryConnectivity
		}
		if reAuth.MatchString(stderr) {
			return CategoryAuthExpired
		}
		// A deadline without detail is still a connectivity/timeout story,
		// not a missing API.
		return CategoryTimeout
	}
	s := strings.TrimSpace(stderr)
	switch {
	case s == "":
		return CategoryUnknown
	case reDeny.MatchString(s):
		return CategoryDenied
	case reAuth.MatchString(s):
		return CategoryAuthExpired
	case reConn.MatchString(s):
		return CategoryConnectivity
	case reCfg.MatchString(s):
		return CategoryConfig
	case reMiss.MatchString(s):
		return CategoryMissing
	default:
		return CategoryUnknown
	}
}

// Remediation returns a short next step for a category. It never includes
// credentials, tokens, or authorization URLs.
func Remediation(c Category) string {
	switch c {
	case CategoryMissing:
		return "Install the missing component or CRDs, then rerun this check. For Kubeflock installs this usually means the Helm chart or the Agent Sandbox controller."
	case CategoryDenied:
		return "Access was denied by RBAC. Ask an administrator for the listed permissions in the configured namespace, then rerun this check."
	case CategoryAuthExpired:
		return "Authentication expired or needs renewal. Complete login in a terminal (for example with your OIDC helper), then rerun this check. Do not paste tokens or codes into logs."
	case CategoryConnectivity:
		return "The API server could not be reached. Check network, VPN, and cluster power, then rerun this check."
	case CategoryTimeout:
		return "The check timed out, possibly while a credential helper waited on a lock. Clear any stuck login helper, then rerun with a longer --timeout."
	case CategoryConfig:
		return "The saved context or kubeconfig is wrong. Run: kubeflock cluster config --context NAME --namespace NAME"
	default:
		return "Rerun with --output json for detail, fix the reported item, then rerun this check."
	}
}
