// ABOUTME: BackendError is a typed error carrying a privd wire cause from backend implementations.
// ABOUTME: Portable — used by server.go on all platforms; implementations are linux-only.
package privd

import (
	"errors"
	"fmt"
)

// BackendError is a typed error that carries a privd wire cause.
// Backend paths that need a specific wire cause (e.g. digest_mismatch, invalid_state)
// return *BackendError; server handlers unwrap it via errors.As and use its Cause.
type BackendError struct {
	Cause   string // wire cause code: digest_mismatch | invalid_state | ...
	Message string // safe human detail; no secrets, no raw host paths outside approved roots
}

func (e *BackendError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("privd backend %s: %s", e.Cause, e.Message)
	}
	return fmt.Sprintf("privd backend %s", e.Cause)
}

// AsBackendError reports whether err (or any error it wraps) is a *BackendError,
// and if so, sets target. Thin wrapper around errors.As for callers that need to
// reference this package without importing errors directly.
func AsBackendError(err error, target **BackendError) bool {
	return errors.As(err, target)
}
