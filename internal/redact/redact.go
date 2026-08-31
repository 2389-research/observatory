// ABOUTME: The single redaction pass applied to operator text and attention
// ABOUTME: summaries before persistence (SPEC §15.3). Versioned by PolicyID.
package redact

import "regexp"

// PolicyID names the active redaction policy. Records that were changed by
// this pass carry it, so evidence states which rules ran (SPEC §15.3: record
// policy version without storing the secret).
const PolicyID = "rp1"

// marker replaces matched secret material. It embeds the policy id so a
// redacted record is self-describing.
const marker = "[redacted:" + PolicyID + "]"

// The patterns cover what §15.3 names for text fields: authorization and
// cookie headers, and bare credential grants. Configured secret literals are
// not implemented yet: no config key exists to supply them.
var patterns = []*regexp.Regexp{
	// Header-shaped: "Authorization: ...", "Cookie: a=b; c=d" — the value to
	// end of line is secret material.
	regexp.MustCompile(`(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+`),
	// Bare grants: "Bearer <token>" / "Basic <base64>" outside header shape.
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`),
}

// Apply redacts s under the active policy. It reports whether anything
// changed; callers persist the returned text, never the input.
func Apply(s string) (string, bool) {
	out := s
	for _, p := range patterns {
		out = p.ReplaceAllStringFunc(out, func(m string) string {
			// Keep the field name (before ':' or the grant scheme word) so the
			// record still says what kind of secret was here.
			loc := p.FindStringSubmatchIndex(m)
			return m[loc[2]:loc[3]] + " " + marker
		})
	}
	return out, out != s
}
