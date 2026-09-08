package check

import (
	"regexp"
	"strings"
)

// Redact removes credential-like values from kubectl output before it is
// shown to users or stored in Herdr logs. It errs toward redacting too much
// rather than leaking a token or authorization code.
var (
	reBearer      = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/=]+`)
	reTokenAssign = regexp.MustCompile(`(?i)((?:id[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization[_-]?code|auth[_-]?code)\s*[:=]\s*)[^\s;,}"]+`)
	reCodeParam   = regexp.MustCompile(`(?i)([?&](?:code|token|id_token|access_token|refresh_token)=)[^&\s;,}"]+`)
	reJWT         = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
)

func redactString(s string) string {
	s = reBearer.ReplaceAllString(s, "bearer [redacted]")
	s = reTokenAssign.ReplaceAllString(s, "${1}[redacted]")
	s = reCodeParam.ReplaceAllString(s, "${1}[redacted]")
	s = reJWT.ReplaceAllString(s, "[redacted-jwt]")
	return s
}

// SanitizeLines redacts each line and drops lines that still look like they
// carry raw credential material (for example an OIDC login URL with an
// embedded code that pattern matching could not fully parse).
func SanitizeLines(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		r := redactString(l)
		low := strings.ToLower(r)
		if strings.Contains(low, "verification_url") && strings.Contains(low, "user_code") {
			continue
		}
		if strings.Contains(low, "authorize") && strings.Contains(low, "code=") && strings.Contains(low, "[redacted]") {
			// Keep the redacted hint line; drop the raw URL if redaction missed.
			out = append(out, "authorization URL omitted; complete login in a terminal")
			continue
		}
		out = append(out, r)
	}
	// Trim trailing empty lines but keep internal structure.
	res := strings.Join(out, "\n")
	return strings.Trim(res, "\n")
}
