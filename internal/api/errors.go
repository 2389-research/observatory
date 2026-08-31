// ABOUTME: The structured error contract (P-06): typed code and cause,
// ABOUTME: retryability, safe details, and executable remediation with rationale.
package api

import (
	"encoding/json"
	"net/http"
)

// Error is the body of every non-2xx API response. Codes and causes are stable
// tokens an agent can branch on; Message is for humans reading the same data.
type Error struct {
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	Retryable   bool           `json:"retryable"`
	Cause       string         `json:"cause"`
	OperationID string         `json:"operation_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	Remediation []Remediation  `json:"remediation,omitempty"`
}

// Remediation is a suggested, never auto-executed, typed next step.
type Remediation struct {
	Action    string         `json:"action"`
	Params    map[string]any `json:"params,omitempty"`
	Rationale string         `json:"rationale"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// Encoding failures here have nowhere better to go; the status line is
	// already committed.
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, e Error) {
	writeJSON(w, status, e)
}

func metaRemediation() Remediation {
	return Remediation{
		Action:    "get",
		Params:    map[string]any{"path": "/api/v1/meta"},
		Rationale: "the manifest lists the routes and features this build actually serves",
	}
}
