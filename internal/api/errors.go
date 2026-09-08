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
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	RetryStrategy string         `json:"retry_strategy"`
	Retryable     bool           `json:"retryable"`
	Cause         string         `json:"cause"`
	OperationID   string         `json:"operation_id,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
	Remediation   []Remediation  `json:"remediation,omitempty"`
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
	if e.OperationID != "" {
		target := basePath + "/operations/" + e.OperationID
		found := false
		for _, step := range e.Remediation {
			if step.Action == "get" && step.Params["path"] == target {
				found = true
			}
		}
		if !found {
			e.Remediation = append(e.Remediation, Remediation{Action: "get", Params: map[string]any{"path": target}, Rationale: "inspect the durable operation before attempting another mutation"})
		}
	}

	if e.RetryStrategy == "" {
		e.RetryStrategy = "never"
		switch {
		case e.Code == "revision_mismatch" || e.Cause == "cursor_invalid":
			e.RetryStrategy = "after_refresh"
		case e.OperationID != "":
			e.RetryStrategy = "query_operation"
		case e.Code == "limit_exceeded" || e.Cause == "admission_refused" || e.Retryable:
			e.RetryStrategy = "after_precondition"
		}
	}

	writeJSON(w, status, e)
}

func metaRemediation() Remediation {
	return Remediation{
		Action:    "get",
		Params:    map[string]any{"path": "/api/v1/meta"},
		Rationale: "the manifest lists the routes and features this build actually serves",
	}
}
