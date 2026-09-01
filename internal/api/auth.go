// ABOUTME: Authentication boundary: session-cookie and bearer-token
// ABOUTME: middleware, /auth handlers, CSRF and origin enforcement.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/events"
)

// SessionCookieName is the cookie name used for browser sessions.
const SessionCookieName = "vmobs_session"

const csrfHeader = "X-CSRF-Token"

// AuthConfig carries all auth dependencies into the API server. When Enabled is
// false the server injects a local_operator/none identity on every request; the
// /auth/* routes still exist but /login and /logout return 409.
type AuthConfig struct {
	Enabled        bool
	Creds          *auth.Store    // nil when Enabled is false
	Sessions       *auth.Sessions // nil when Enabled is false
	PublicOrigin   string         // e.g. "http://127.0.0.1:8787"
	CookieSameSite http.SameSite
	CookieSecure   bool
	LoginDelay     time.Duration // delay on failed login to bound volume
}

// authState is the per-Server auth state embedded in Server.
type authState struct {
	ac         AuthConfig
	loginMu    sync.Mutex
	authInstID string       // stream identity for auth events from the API layer
	authSeq    atomic.Int64 // monotonic sequence for auth events
}

// withAuth wraps next with the authentication boundary.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt: GET /meta and POST /auth/login pass through with no identity.
		if isExempt(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Auth disabled: inject dev identity, skip all checks.
		if !s.auth.ac.Enabled {
			ctx := auth.WithIdentity(r.Context(), auth.Identity{
				Owner:  "local_operator",
				Method: "none",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Bearer token check.
		if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
			secret := strings.TrimPrefix(hdr, "Bearer ")
			rec, err := s.auth.ac.Creds.VerifyToken(secret)
			if err != nil {
				if errors.Is(err, auth.ErrBadCredentials) {
					writeError(w, http.StatusUnauthorized, Error{
						Code:      "unauthenticated",
						Message:   "the bearer token is invalid, revoked, or expired",
						Retryable: false,
						Cause:     "invalid_token",
						Remediation: []Remediation{{
							Action:    "bearer_token",
							Rationale: "send Authorization: Bearer with a token from vmobs auth token create",
						}},
					})
					return
				}
				writeError(w, http.StatusInternalServerError, Error{
					Code: "internal", Message: "token verification failed", Retryable: true, Cause: "storage_failure",
				})
				return
			}
			ctx := auth.WithIdentity(r.Context(), auth.Identity{
				Owner:   rec.Owner,
				Method:  "token",
				TokenID: rec.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Session cookie check.
		if c, err := r.Cookie(SessionCookieName); err == nil {
			sess, ok := s.auth.ac.Sessions.Get(c.Value)
			if !ok {
				// Expire the cookie in the response so the browser clears it.
				http.SetCookie(w, &http.Cookie{
					Name:     SessionCookieName,
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					SameSite: s.auth.ac.CookieSameSite,
					Secure:   s.auth.ac.CookieSecure,
				})
				writeError(w, http.StatusUnauthorized, Error{
					Code:      "unauthenticated",
					Message:   "the session cookie is invalid or has expired; please log in again",
					Retryable: false,
					Cause:     "session_invalid_or_expired",
					Remediation: []Remediation{{
						Action:    "login",
						Params:    map[string]any{"method": "POST", "path": basePath + "/auth/login"},
						Rationale: "obtain a new session cookie",
					}},
				})
				return
			}

			// CSRF + origin check for state-changing methods.
			if isMutating(r.Method) {
				if origin := r.Header.Get("Origin"); origin != "" && origin != s.auth.ac.PublicOrigin {
					writeError(w, http.StatusForbidden, Error{
						Code:      "forbidden",
						Message:   "the Origin header does not match the configured public origin",
						Retryable: false,
						Cause:     "origin_rejected",
						Remediation: []Remediation{{
							Action:    "check_origin",
							Rationale: "requests must originate from the configured public_origin",
						}},
					})
					return
				}
				token := r.Header.Get(csrfHeader)
				if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
					writeError(w, http.StatusForbidden, Error{
						Code:      "forbidden",
						Message:   "the X-CSRF-Token header is missing or incorrect",
						Retryable: false,
						Cause:     "csrf_rejected",
						Remediation: []Remediation{{
							Action:    "get_csrf_token",
							Params:    map[string]any{"path": basePath + "/auth/session"},
							Rationale: "GET /api/v1/auth/session and send its csrf_token in X-CSRF-Token",
						}},
					})
					return
				}
			}

			ctx := auth.WithIdentity(r.Context(), auth.Identity{
				Owner:     sess.Owner,
				Method:    "session",
				SessionID: sess.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// No credentials presented.
		writeError(w, http.StatusUnauthorized, Error{
			Code:      "unauthenticated",
			Message:   "this endpoint requires authentication; provide a session cookie or a bearer token",
			Retryable: false,
			Cause:     "no_credentials",
			Remediation: []Remediation{
				{
					Action:    "login",
					Params:    map[string]any{"method": "POST", "path": basePath + "/auth/login"},
					Rationale: "obtain a session cookie",
				},
				{
					Action:    "bearer_token",
					Rationale: "send Authorization: Bearer with a token from vmobs auth token create",
				},
			},
		})
	})
}

// isExempt reports whether the route is outside the auth boundary.
// GET /meta and POST /auth/login never require credentials.
func isExempt(r *http.Request) bool {
	path := r.URL.Path
	if r.Method == http.MethodGet && path == basePath+"/meta" {
		return true
	}
	if r.Method == http.MethodPost && path == basePath+"/auth/login" {
		return true
	}
	return false
}

// isMutating reports whether the method changes state and therefore requires CSRF.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// handleAuthLogin handles POST /auth/login.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.ac.Enabled {
		writeError(w, http.StatusConflict, Error{
			Code:      "auth_disabled",
			Message:   "authentication is not required in this configuration; all requests run as local_operator",
			Retryable: false,
			Cause:     "auth_disabled",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/auth/session"},
				Rationale: "check the current identity",
			}},
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "login body must be {\"username\": ..., \"password\": ...}",
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// Serialize all login attempts through one mutex to bound concurrent argon2 work.
	s.auth.loginMu.Lock()
	owner, err := s.auth.ac.Creds.VerifyPassword(body.Username, body.Password)
	s.auth.loginMu.Unlock()

	if err != nil {
		// Truncate username to 64 bytes for the event.
		usernameForEvent := body.Username
		truncated := false
		if len(usernameForEvent) > 64 {
			usernameForEvent = usernameForEvent[:64]
			truncated = true
		}
		data := map[string]any{
			"username":    usernameForEvent,
			"remote_addr": r.RemoteAddr,
		}
		if truncated {
			data["truncated"] = true
		}
		_ = s.appendAuthEvent(r, "auth.login_failed", data)
		time.Sleep(s.auth.ac.LoginDelay)
		writeError(w, http.StatusUnauthorized, Error{
			Code:      "unauthenticated",
			Message:   "invalid username or password",
			Retryable: false,
			Cause:     "invalid_credentials",
		})
		return
	}

	sess := s.auth.ac.Sessions.Create(owner)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: s.auth.ac.CookieSameSite,
		Secure:   s.auth.ac.CookieSecure,
	})

	_ = s.appendAuthEvent(r, "auth.session_created", map[string]any{
		"owner":       owner,
		"remote_addr": r.RemoteAddr,
		"expires_at":  sess.ExpiresAt.UTC().Format(time.RFC3339),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"owner":      owner,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
		"csrf_token": sess.CSRFToken,
	})
}

// handleAuthLogout handles POST /auth/logout.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if !s.auth.ac.Enabled {
		writeError(w, http.StatusConflict, Error{
			Code:      "auth_disabled",
			Message:   "authentication is not required in this configuration; all requests run as local_operator",
			Retryable: false,
			Cause:     "auth_disabled",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/auth/session"},
				Rationale: "check the current identity",
			}},
		})
		return
	}

	id, ok := auth.IdentityFrom(r.Context())
	if !ok || id.Method != "session" {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "bad_request",
			Message:   "logout requires a session identity; bearer token sessions cannot be ended this way",
			Retryable: false,
			Cause:     "not_a_session",
		})
		return
	}

	s.auth.ac.Sessions.Revoke(id.SessionID)

	// Expire the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: s.auth.ac.CookieSameSite,
		Secure:   s.auth.ac.CookieSecure,
	})

	_ = s.appendAuthEvent(r, "auth.session_ended", map[string]any{
		"owner":  id.Owner,
		"reason": "logout",
	})

	writeJSON(w, http.StatusOK, map[string]any{"ended": true})
}

// handleAuthSession handles GET /auth/session — always available regardless of auth mode.
func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		// Auth is off and the middleware injected nothing (shouldn't happen but be safe).
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":  "local_operator",
			"method": "none",
		})
		return
	}
	switch id.Method {
	case "session":
		sess, sessOK := s.auth.ac.Sessions.Get(id.SessionID)
		if !sessOK {
			writeError(w, http.StatusUnauthorized, Error{
				Code:      "unauthenticated",
				Message:   "session expired",
				Retryable: false,
				Cause:     "session_invalid_or_expired",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":      id.Owner,
			"method":     "session",
			"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
			"csrf_token": sess.CSRFToken,
		})
	case "token":
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":    id.Owner,
			"method":   "token",
			"token_id": id.TokenID,
		})
	default: // "none"
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":  id.Owner,
			"method": "none",
		})
	}
}

// appendAuthEvent emits a host-observed auth event on the API server's own stream.
// Failures are logged but do not affect the response.
func (s *Server) appendAuthEvent(r *http.Request, kind string, data map[string]any) error {
	seq := s.auth.authSeq.Add(1)
	env := &events.Envelope{
		SchemaVersion:    1,
		SourceInstanceID: s.auth.authInstID,
		SourceSeq:        strconv.FormatInt(seq, 10),
		Kind:             kind,
		Provenance:       events.HostObserved,
		Sensor:           "api",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}
	_, err := s.store.Append(r.Context(), env)
	return err
}

// handleTokenCreate handles POST /auth/tokens.
func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.auth.ac.Enabled {
		writeError(w, http.StatusConflict, Error{
			Code:      "auth_disabled",
			Message:   "authentication is not required in this configuration; all requests run as local_operator",
			Retryable: false,
			Cause:     "auth_disabled",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/auth/session"},
				Rationale: "check the current identity",
			}},
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Name       string `json:"name"`
		TTLMinutes *int   `json:"ttl_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "body must be {\"name\": ..., \"ttl_minutes\": ...}",
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// Validate name: required, max 128 bytes.
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, Error{
			Code:    "validation_failed",
			Message: "name is required",
			Cause:   "name_required",
		})
		return
	}
	if len(body.Name) > 128 {
		writeError(w, http.StatusBadRequest, Error{
			Code:    "validation_failed",
			Message: "name must be 128 bytes or fewer",
			Cause:   "name_too_long",
			Remediation: []Remediation{{
				Action:    "shorten_name",
				Rationale: "token names are bounded to 128 bytes",
			}},
		})
		return
	}

	// Owner comes from the authenticated identity — never from the request body.
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "no identity in context",
			Retryable: false,
			Cause:     "no_identity",
		})
		return
	}

	// ttl_minutes ≤ 0 or absent → no expiry.
	var ttl time.Duration
	if body.TTLMinutes != nil && *body.TTLMinutes > 0 {
		ttl = time.Duration(*body.TTLMinutes) * time.Minute
	}

	secret, rec, err := s.auth.ac.Creds.CreateToken(body.Name, id.Owner, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "failed to create token",
			Retryable: true,
			Cause:     "storage_failure",
		})
		return
	}

	_ = s.appendAuthEvent(r, "auth.token_created", map[string]any{
		"token_id": rec.ID,
		"name":     rec.Name,
		"owner":    rec.Owner,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"token": map[string]any{
			"id":         rec.ID,
			"name":       rec.Name,
			"owner":      rec.Owner,
			"created_at": rec.CreatedAt,
			"expires_at": rec.ExpiresAt,
		},
		"secret": secret,
	})
}

// handleTokenList handles GET /auth/tokens.
func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request) {
	if !s.auth.ac.Enabled {
		writeError(w, http.StatusConflict, Error{
			Code:      "auth_disabled",
			Message:   "authentication is not required in this configuration; all requests run as local_operator",
			Retryable: false,
			Cause:     "auth_disabled",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/auth/session"},
				Rationale: "check the current identity",
			}},
		})
		return
	}

	records, err := s.auth.ac.Creds.ListTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "failed to list tokens",
			Retryable: true,
			Cause:     "storage_failure",
		})
		return
	}

	// Build wire tokens — metadata only, never the secret or hash.
	type wireToken struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Owner     string `json:"owner"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		RevokedAt string `json:"revoked_at"`
	}
	out := make([]wireToken, 0, len(records))
	for _, rec := range records {
		out = append(out, wireToken{
			ID:        rec.ID,
			Name:      rec.Name,
			Owner:     rec.Owner,
			CreatedAt: rec.CreatedAt,
			ExpiresAt: rec.ExpiresAt,
			RevokedAt: rec.RevokedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// handleTokenRevoke handles DELETE /auth/tokens/{id}.
func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.auth.ac.Enabled {
		writeError(w, http.StatusConflict, Error{
			Code:      "auth_disabled",
			Message:   "authentication is not required in this configuration; all requests run as local_operator",
			Retryable: false,
			Cause:     "auth_disabled",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/auth/session"},
				Rationale: "check the current identity",
			}},
		})
		return
	}

	tokenID := r.PathValue("id")
	if tokenID == "" {
		writeError(w, http.StatusBadRequest, Error{
			Code:    "bad_request",
			Message: "token id is required in the path",
			Cause:   "id_missing",
		})
		return
	}

	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "no identity in context",
			Retryable: false,
			Cause:     "no_identity",
		})
		return
	}

	err := s.auth.ac.Creds.RevokeToken(tokenID)
	if errors.Is(err, auth.ErrTokenNotFound) {
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "token not found",
			Retryable: false,
			Cause:     "token_not_found",
		})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "failed to revoke token",
			Retryable: true,
			Cause:     "storage_failure",
		})
		return
	}

	// owner here is the ACTING caller's identity (audit semantics), not
	// necessarily the token's owner — a privileged caller can revoke others' tokens.
	_ = s.appendAuthEvent(r, "auth.token_revoked", map[string]any{
		"token_id": tokenID,
		"owner":    id.Owner,
	})

	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func initAuthState(ac AuthConfig) authState {
	return authState{
		ac:         ac,
		authInstID: uuid.NewString(),
	}
}
