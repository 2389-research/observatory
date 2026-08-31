// ABOUTME: Tests the versioned redaction pass applied to operator text and
// ABOUTME: attention summaries before persistence (SPEC §15.3).
package redact_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/redact"
)

func TestPolicyIDStable(t *testing.T) {
	// The policy id is recorded on redacted records; changing it is a contract
	// change, not a refactor.
	if redact.PolicyID != "rp1" {
		t.Errorf("PolicyID = %q", redact.PolicyID)
	}
}

func TestRedactsCredentialShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		keep string // substring that must survive
		gone string // substring that must not survive
	}{
		{
			"authorization header",
			"request failed with Authorization: Bearer sk-live-abc123def456 retried twice",
			"request failed",
			"sk-live-abc123def456",
		},
		{
			"cookie header",
			"saw Cookie: session=deadbeefcafe1234; theme=dark in the capture",
			"saw",
			"deadbeefcafe1234",
		},
		{
			"proxy authorization",
			"Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==",
			"",
			"dXNlcjpwYXNzd29yZA==",
		},
		{
			"bare bearer token",
			"the run used bearer eyJhbGciOiJIUzI1NiJ9.payload.sig against the API",
			"against the API",
			"eyJhbGciOiJIUzI1NiJ9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, changed := redact.Apply(tc.in)
			if !changed {
				t.Fatalf("Apply(%q) reported no change", tc.in)
			}
			if tc.keep != "" && !strings.Contains(out, tc.keep) {
				t.Errorf("lost innocent text %q: %q", tc.keep, out)
			}
			if strings.Contains(out, tc.gone) {
				t.Errorf("secret %q survived: %q", tc.gone, out)
			}
			if !strings.Contains(out, "[redacted:"+redact.PolicyID+"]") {
				t.Errorf("redaction not marked with policy id: %q", out)
			}
		})
	}
}

func TestPlainTextPassesThrough(t *testing.T) {
	for _, in := range []string{
		"the build failed on step 3; see /workspace/log.txt",
		"cookie consent banner blocked the click",
		"",
		"basic idea: retry with backoff",
	} {
		out, changed := redact.Apply(in)
		if changed || out != in {
			t.Errorf("Apply(%q) = %q, changed=%v; want passthrough", in, out, changed)
		}
	}
}
