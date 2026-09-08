// ABOUTME: Tests for the auth middleware, /auth endpoints, CSRF, and origin checks.
// ABOUTME: Real HTTP against real SQLite; no mocks.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/auth"
	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

const (
	testOperator = "local_operator"
	testPassword = "correct-horse-battery"
	testOrigin   = "http://127.0.0.1:8787"
)

// newAuthServer creates a server with auth enabled and a credential store seeded
// with testOperator / testPassword. Returns the server and the cred store.
func newAuthServer(t *testing.T) (*httptest.Server, *store.Store, *auth.Store) {
	t.Helper()
	return newAuthServerInDir(t, t.TempDir())
}

func newAuthServerInDir(t *testing.T, dir string) (*httptest.Server, *store.Store, *auth.Store) {
	t.Helper()
	credDir := filepath.Join(dir, "creds")
	credStore, err := auth.InitStore(credDir, testOperator, testPassword)
	if err != nil {
		t.Fatalf("init cred store: %v", err)
	}

	st, err := store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"lifecycle_failed": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	sessions := auth.NewSessions(time.Hour)
	ac := api.AuthConfig{
		Enabled:        true,
		Creds:          credStore,
		Sessions:       sessions,
		PublicOrigin:   testOrigin,
		CookieSameSite: http.SameSiteStrictMode,
		CookieSecure:   false,
		LoginDelay:     time.Millisecond,
	}

	srv := httptest.NewServer(api.New(st, eng, mgr, ac, nil, nil))
	t.Cleanup(srv.Close)
	return srv, st, credStore
}

// loginAndGetSession performs a login and returns the CSRF token and a client with cookies.
func loginAndGetSession(t *testing.T, srvURL string) (csrfToken string, client *http.Client) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	client = &http.Client{Jar: jar}

	body := `{"username":"local_operator","password":"correct-horse-battery"}`
	resp, err := client.Post(srvURL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: %d\n%s", resp.StatusCode, raw)
	}
	var loginResp struct {
		Owner     string `json:"owner"`
		ExpiresAt string `json:"expires_at"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return loginResp.CSRFToken, client
}

// doWithCSRF sends method+path with cookie jar and CSRF header.
func doWithCSRF(t *testing.T, client *http.Client, method, url, csrfToken string, body io.Reader, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func TestUnauthenticatedRequestsDenied(t *testing.T) {
	srv, _, _ := newAuthServer(t)

	// GET /meta is exempt — must always answer 200.
	resp, err := http.Get(srv.URL + "/api/v1/meta")
	if err != nil {
		t.Fatalf("GET /meta: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /meta with auth on: want 200, got %d", resp.StatusCode)
	}

	// Everything else without credentials → 401 with remediation pointing at /auth/login.
	for _, probe := range []struct{ method, path string }{
		{"GET", "/api/v1/vms"},
		{"GET", "/api/v1/events"},
		{"POST", "/api/v1/vms"},
	} {
		req, _ := http.NewRequest(probe.method, srv.URL+probe.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", probe.method, probe.path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: want 401, got %d\n%s", probe.method, probe.path, resp.StatusCode, raw)
			continue
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode 401 body: %v\n%s", err, raw)
		}
		if e.Code != "unauthenticated" {
			t.Errorf("%s %s: code = %q, want unauthenticated", probe.method, probe.path, e.Code)
		}
		if len(e.Remediation) == 0 {
			t.Errorf("%s %s: 401 must carry remediation", probe.method, probe.path)
		}
		foundLogin := false
		for _, r := range e.Remediation {
			if p, ok := r.Params["path"]; ok && strings.Contains(fmt.Sprint(p), "/api/v1/auth/login") {
				foundLogin = true
			}
		}
		if !foundLogin {
			t.Errorf("%s %s: remediation must mention /api/v1/auth/login: %+v", probe.method, probe.path, e.Remediation)
		}
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	srv, _, _ := newAuthServer(t)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	// Login with correct credentials.
	body := `{"username":"local_operator","password":"correct-horse-battery"}`
	resp, err := client.Post(srv.URL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: want 200, got %d\n%s", resp.StatusCode, raw)
	}

	var loginResp struct {
		Owner     string `json:"owner"`
		ExpiresAt string `json:"expires_at"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(raw, &loginResp); err != nil {
		t.Fatalf("decode login: %v\n%s", err, raw)
	}
	if loginResp.Owner == "" || loginResp.ExpiresAt == "" || loginResp.CSRFToken == "" {
		t.Errorf("login response missing fields: %+v", loginResp)
	}

	// Extract the session cookie value before the jar might clear it on logout.
	var sessionCookieVal string
	for _, c := range resp.Cookies() {
		if c.Name == api.SessionCookieName {
			sessionCookieVal = c.Value
		}
	}

	// Verify Set-Cookie attributes.
	cookieHdr := resp.Header.Get("Set-Cookie")
	if !strings.Contains(cookieHdr, "vmobs_session") {
		t.Errorf("Set-Cookie missing vmobs_session: %q", cookieHdr)
	}
	if !strings.Contains(cookieHdr, "HttpOnly") {
		t.Errorf("Set-Cookie missing HttpOnly: %q", cookieHdr)
	}
	if !strings.Contains(cookieHdr, "SameSite=Strict") {
		t.Errorf("Set-Cookie missing SameSite=Strict: %q", cookieHdr)
	}
	if !strings.Contains(cookieHdr, "Path=/") {
		t.Errorf("Set-Cookie missing Path=/: %q", cookieHdr)
	}

	// GET /auth/session with cookie — no CSRF header needed for GET.
	sessResp, err := client.Get(srv.URL + "/api/v1/auth/session")
	if err != nil {
		t.Fatalf("GET /auth/session: %v", err)
	}
	sessRaw, _ := io.ReadAll(sessResp.Body)
	sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/session: want 200, got %d\n%s", sessResp.StatusCode, sessRaw)
	}
	var sessBody struct {
		Owner  string `json:"owner"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(sessRaw, &sessBody); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sessBody.Owner != testOperator || sessBody.Method != "session" {
		t.Errorf("session: owner=%q method=%q, want %q/session", sessBody.Owner, sessBody.Method, testOperator)
	}

	// POST /auth/logout with cookie + CSRF.
	logoutReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/logout", nil)
	logoutReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	logoutRaw, _ := io.ReadAll(logoutResp.Body)
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout: want 200, got %d\n%s", logoutResp.StatusCode, logoutRaw)
	}

	// After logout, sending the old session cookie must be rejected.
	// The cookie jar has cleared the cookie (MaxAge=-1), so send it manually.
	afterReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/vms", nil)
	if sessionCookieVal != "" {
		afterReq.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: sessionCookieVal})
	}
	afterResp, err := http.DefaultClient.Do(afterReq)
	if err != nil {
		t.Fatalf("after logout GET /vms: %v", err)
	}
	afterRaw, _ := io.ReadAll(afterResp.Body)
	afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: want 401, got %d\n%s", afterResp.StatusCode, afterRaw)
	}
	var afterErr api.Error
	if err := json.Unmarshal(afterRaw, &afterErr); err != nil {
		t.Fatalf("decode post-logout error: %v", err)
	}
	if afterErr.Cause != "session_invalid_or_expired" {
		t.Errorf("post-logout cause = %q, want session_invalid_or_expired", afterErr.Cause)
	}
}

func TestLoginBadPassword(t *testing.T) {
	srv, st, _ := newAuthServer(t)

	body := `{"username":"local_operator","password":"wrong-password"}`
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: want 401, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if e.Code != "unauthenticated" || e.Cause != "invalid_credentials" {
		t.Errorf("bad password: code=%q cause=%q, want unauthenticated/invalid_credentials", e.Code, e.Cause)
	}

	// Verify a login_failed event was recorded.
	// No sleep needed: appendAuthEvent is synchronous, completing before the 401
	// response is written, so receiving the response guarantees the event is stored.
	result, err := st.Query(context.Background(), store.Query{Kind: "auth.login_failed", Limit: 10})
	if err != nil {
		t.Fatalf("query login_failed: %v", err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected at least one auth.login_failed event")
	}

	// The raw event data must not contain the password.
	for _, env := range result.Events {
		payload, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		if strings.Contains(string(payload), "wrong-password") {
			t.Errorf("login_failed event contains the password: %s", payload)
		}
	}
}

func TestCSRFEnforced(t *testing.T) {
	srv, st, _ := newAuthServer(t)
	csrfToken, client := loginAndGetSession(t, srv.URL)

	annotationURL := srv.URL + "/api/v1/annotations"
	annotationBody := `{"target_ref":"host:main","text":"csrf test annotation"}`

	// POST without CSRF token → 403 csrf_rejected.
	resp := doWithCSRF(t, client, http.MethodPost, annotationURL, "", strings.NewReader(annotationBody), "application/json")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF: want 403, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode 403: %v\n%s", err, raw)
	}
	if e.Cause != "csrf_rejected" {
		t.Errorf("no CSRF: cause = %q, want csrf_rejected", e.Cause)
	}

	// Verify annotation was NOT created.
	listResp, err := client.Get(srv.URL + "/api/v1/annotations")
	if err != nil {
		t.Fatalf("list annotations: %v", err)
	}
	listRaw, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	var listBody struct {
		Annotations []any `json:"annotations"`
	}
	if err := json.Unmarshal(listRaw, &listBody); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listBody.Annotations) != 0 {
		t.Errorf("annotation was created despite csrf rejection; list has %d items", len(listBody.Annotations))
	}

	// Wrong token → 403.
	resp2 := doWithCSRF(t, client, http.MethodPost, annotationURL, "wrong-token", strings.NewReader(annotationBody), "application/json")
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong CSRF: want 403, got %d\n%s", resp2.StatusCode, raw2)
	}

	// Correct token → 201.
	resp3 := doWithCSRF(t, client, http.MethodPost, annotationURL, csrfToken, strings.NewReader(annotationBody), "application/json")
	raw3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("correct CSRF: want 201, got %d\n%s", resp3.StatusCode, raw3)
	}

	// Query store directly to confirm AT-079 evidence.
	result, err := st.Query(context.Background(), store.Query{Kind: "annotation.created", Limit: 10})
	if err != nil {
		t.Fatalf("query annotations: %v", err)
	}
	if len(result.Events) != 1 {
		t.Errorf("expected 1 annotation.created event, got %d", len(result.Events))
	}
}

func TestOriginChecked(t *testing.T) {
	srv, _, _ := newAuthServer(t)
	csrfToken, client := loginAndGetSession(t, srv.URL)

	annotationURL := srv.URL + "/api/v1/annotations"
	annotationBody := `{"target_ref":"host:main","text":"origin test"}`

	// Evil origin → 403 origin_rejected.
	req, _ := http.NewRequest(http.MethodPost, annotationURL, strings.NewReader(annotationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("evil origin: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("evil origin: want 403, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Cause != "origin_rejected" {
		t.Errorf("evil origin cause = %q, want origin_rejected", e.Cause)
	}

	// Correct origin + CSRF → 201.
	req2, _ := http.NewRequest(http.MethodPost, annotationURL, strings.NewReader(annotationBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-CSRF-Token", csrfToken)
	req2.Header.Set("Origin", testOrigin)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("good origin: %v", err)
	}
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("good origin: want 201, got %d\n%s", resp2.StatusCode, raw2)
	}
}

func TestAuthDisabledInjectsLocalOperator(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil, nil))
	t.Cleanup(srv.Close)

	// GET /vms without credentials → 200 (dev identity injected).
	resp, err := http.Get(srv.URL + "/api/v1/vms")
	if err != nil {
		t.Fatalf("GET /vms: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("auth disabled GET /vms: want 200, got %d", resp.StatusCode)
	}

	// GET /auth/session → 200 with method: none.
	sessResp, err := http.Get(srv.URL + "/api/v1/auth/session")
	if err != nil {
		t.Fatalf("GET /auth/session: %v", err)
	}
	sessRaw, _ := io.ReadAll(sessResp.Body)
	sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("auth/session: want 200, got %d\n%s", sessResp.StatusCode, sessRaw)
	}
	var sessBody struct {
		Owner  string `json:"owner"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(sessRaw, &sessBody); err != nil {
		t.Fatalf("decode session: %v\n%s", err, sessRaw)
	}
	if sessBody.Owner != testOperator || sessBody.Method != "none" {
		t.Errorf("session: owner=%q method=%q, want %q/none", sessBody.Owner, sessBody.Method, testOperator)
	}

	// POST /auth/login → 409 auth_disabled.
	resp2, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"x","password":"y"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("login with auth disabled: want 409, got %d\n%s", resp2.StatusCode, raw2)
	}
	var e2 api.Error
	if err := json.Unmarshal(raw2, &e2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e2.Code != "auth_disabled" {
		t.Errorf("code = %q, want auth_disabled", e2.Code)
	}

	// POST /auth/logout → 409 auth_disabled (spec: every auth endpoint except
	// GET /auth/session returns 409 auth_disabled when auth is off).
	resp3, err := http.Post(srv.URL+"/api/v1/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	raw3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("logout with auth disabled: want 409, got %d\n%s", resp3.StatusCode, raw3)
	}
	var e3 api.Error
	if err := json.Unmarshal(raw3, &e3); err != nil {
		t.Fatalf("decode logout error: %v\n%s", err, raw3)
	}
	if e3.Cause != "auth_disabled" {
		t.Errorf("logout auth_disabled cause = %q, want auth_disabled", e3.Cause)
	}
}

func TestSessionEventsEmitted(t *testing.T) {
	srv, st, _ := newAuthServer(t)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	// Login.
	body := `{"username":"local_operator","password":"correct-horse-battery"}`
	loginResp, err := client.Post(srv.URL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginRaw, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: want 200, got %d", loginResp.StatusCode)
	}

	// Extract session cookie value from the jar.
	var sessionCookieValue string
	for _, c := range jar.Cookies(loginResp.Request.URL) {
		if c.Name == "vmobs_session" {
			sessionCookieValue = c.Value
		}
	}
	// Also check raw Set-Cookie header for the cookie value.
	cookieHdr := loginResp.Header.Get("Set-Cookie")
	if sessionCookieValue == "" {
		// Parse from header as fallback.
		for _, part := range strings.Split(cookieHdr, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "vmobs_session=") {
				sessionCookieValue = strings.TrimPrefix(part, "vmobs_session=")
			}
		}
	}

	var loginBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginRaw, &loginBody); err != nil {
		t.Fatalf("decode login: %v", err)
	}

	// Logout.
	logoutReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/logout", nil)
	logoutReq.Header.Set("X-CSRF-Token", loginBody.CSRFToken)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout: want 200, got %d", logoutResp.StatusCode)
	}

	// Check auth.session_created event exists.
	createdResult, err := st.Query(context.Background(), store.Query{Kind: "auth.session_created", Limit: 10})
	if err != nil {
		t.Fatalf("query session_created: %v", err)
	}
	if len(createdResult.Events) == 0 {
		t.Fatal("expected auth.session_created event")
	}

	// Check auth.session_ended event exists.
	endedResult, err := st.Query(context.Background(), store.Query{Kind: "auth.session_ended", Limit: 10})
	if err != nil {
		t.Fatalf("query session_ended: %v", err)
	}
	if len(endedResult.Events) == 0 {
		t.Fatal("expected auth.session_ended event")
	}

	// Neither event's payload should contain the session cookie value.
	if sessionCookieValue == "" {
		t.Fatalf("could not extract session cookie for event assertion")
	}
	for _, env := range append(createdResult.Events, endedResult.Events...) {
		payload, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(payload), sessionCookieValue) {
			t.Errorf("event payload contains session cookie value: %s", payload)
		}
	}

	// Sanity: events are host_observed.
	for _, env := range createdResult.Events {
		if env.Provenance != events.HostObserved {
			t.Errorf("session_created: provenance = %q, want host_observed", env.Provenance)
		}
	}
}

// TestTokenLifecycleOverAPI exercises the full create→use→list→revoke path.
func TestTokenLifecycleOverAPI(t *testing.T) {
	srv, st, _ := newAuthServer(t)
	csrfToken, client := loginAndGetSession(t, srv.URL)

	// POST /auth/tokens — create a token.
	createResp := doWithCSRF(t, client, http.MethodPost, srv.URL+"/api/v1/auth/tokens",
		csrfToken, strings.NewReader(`{"name":"ci"}`), "application/json")
	createRaw, _ := io.ReadAll(createResp.Body)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: want 201, got %d\n%s", createResp.StatusCode, createRaw)
	}
	var createBody struct {
		Token struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Owner     string `json:"owner"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(createRaw, &createBody); err != nil {
		t.Fatalf("decode create response: %v\n%s", err, createRaw)
	}
	if !strings.HasPrefix(createBody.Secret, "vmobs_") {
		t.Errorf("secret %q: want vmobs_ prefix", createBody.Secret)
	}
	if createBody.Token.ID == "" {
		t.Error("token id must be non-empty")
	}
	if createBody.Token.Name != "ci" {
		t.Errorf("token name = %q, want ci", createBody.Token.Name)
	}
	if createBody.Token.Owner != testOperator {
		t.Errorf("token owner = %q, want %q", createBody.Token.Owner, testOperator)
	}
	tokenID := createBody.Token.ID
	secret := createBody.Secret

	// Bearer token on GET /vms → 200.
	bearerReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/vms", nil)
	bearerReq.Header.Set("Authorization", "Bearer "+secret)
	bearerResp, err := http.DefaultClient.Do(bearerReq)
	if err != nil {
		t.Fatalf("bearer GET /vms: %v", err)
	}
	bearerResp.Body.Close()
	if bearerResp.StatusCode != http.StatusOK {
		t.Errorf("bearer token: want 200, got %d", bearerResp.StatusCode)
	}

	// GET /auth/tokens — list; must not contain the secret.
	listResp, err := client.Get(srv.URL + "/api/v1/auth/tokens")
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	listRaw, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list tokens: want 200, got %d\n%s", listResp.StatusCode, listRaw)
	}
	var listBody struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(listRaw, &listBody); err != nil {
		t.Fatalf("decode list: %v\n%s", err, listRaw)
	}
	if len(listBody.Tokens) != 1 {
		t.Errorf("list: want 1 token, got %d", len(listBody.Tokens))
	}
	// Raw body must not contain the secret.
	if strings.Contains(string(listRaw), secret) {
		t.Errorf("list response contains the secret: %s", listRaw)
	}

	// DELETE /auth/tokens/{id} → 200.
	revokeResp := doWithCSRF(t, client, http.MethodDelete,
		srv.URL+"/api/v1/auth/tokens/"+tokenID,
		csrfToken, nil, "")
	revokeRaw, _ := io.ReadAll(revokeResp.Body)
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke token: want 200, got %d\n%s", revokeResp.StatusCode, revokeRaw)
	}
	var revokeBody struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.Unmarshal(revokeRaw, &revokeBody); err != nil {
		t.Fatalf("decode revoke: %v\n%s", err, revokeRaw)
	}
	if !revokeBody.Revoked {
		t.Error("revoke: want {revoked: true}")
	}

	// Bearer token is now rejected.
	bearerReq2, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/vms", nil)
	bearerReq2.Header.Set("Authorization", "Bearer "+secret)
	bearerResp2, err := http.DefaultClient.Do(bearerReq2)
	if err != nil {
		t.Fatalf("bearer after revoke: %v", err)
	}
	bearerResp2.Body.Close()
	if bearerResp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("bearer after revoke: want 401, got %d", bearerResp2.StatusCode)
	}

	// auth.token_created and auth.token_revoked events must exist and must not
	// contain the secret in any serialised form.
	for _, kind := range []string{"auth.token_created", "auth.token_revoked"} {
		result, err := st.Query(context.Background(), store.Query{Kind: kind, Limit: 10})
		if err != nil {
			t.Fatalf("query %s: %v", kind, err)
		}
		if len(result.Events) == 0 {
			t.Fatalf("expected at least one %s event", kind)
		}
		for _, env := range result.Events {
			payload, _ := json.Marshal(env)
			if strings.Contains(string(payload), secret) {
				t.Errorf("%s event contains secret: %s", kind, payload)
			}
		}
	}
}

// TestTokenCreateRequiresAuth verifies that unauthenticated requests are rejected
// and that a bearer token identity can mint a successor token.
func TestTokenCreateRequiresAuth(t *testing.T) {
	srv, _, _ := newAuthServer(t)

	// No credentials → 401.
	resp, err := http.Post(srv.URL+"/api/v1/auth/tokens", "application/json",
		strings.NewReader(`{"name":"anon"}`))
	if err != nil {
		t.Fatalf("unauthenticated create: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: want 401, got %d\n%s", resp.StatusCode, raw)
	}

	// Bearer token identity may mint a successor (single-operator V1).
	// First, get a token via session.
	csrfToken, client := loginAndGetSession(t, srv.URL)
	createResp := doWithCSRF(t, client, http.MethodPost, srv.URL+"/api/v1/auth/tokens",
		csrfToken, strings.NewReader(`{"name":"seed"}`), "application/json")
	createRaw, _ := io.ReadAll(createResp.Body)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("session create: want 201, got %d\n%s", createResp.StatusCode, createRaw)
	}
	var seedBody struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(createRaw, &seedBody); err != nil {
		t.Fatalf("decode seed: %v", err)
	}

	// Use the bearer token to create another.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/tokens",
		strings.NewReader(`{"name":"successor"}`))
	req.Header.Set("Authorization", "Bearer "+seedBody.Secret)
	req.Header.Set("Content-Type", "application/json")
	// No CSRF header needed for bearer-only requests (CSRF guard only fires for session cookies).
	succResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bearer mint: %v", err)
	}
	succRaw, _ := io.ReadAll(succResp.Body)
	succResp.Body.Close()
	if succResp.StatusCode != http.StatusCreated {
		t.Fatalf("bearer mint: want 201, got %d\n%s", succResp.StatusCode, succRaw)
	}
}

// TestTokenTTL verifies that ttl_minutes produces a non-empty expires_at ≈ now+TTL.
func TestTokenTTL(t *testing.T) {
	srv, _, _ := newAuthServer(t)
	csrfToken, client := loginAndGetSession(t, srv.URL)

	before := time.Now()
	resp := doWithCSRF(t, client, http.MethodPost, srv.URL+"/api/v1/auth/tokens",
		csrfToken, strings.NewReader(`{"name":"short","ttl_minutes":1}`), "application/json")
	after := time.Now()
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create with TTL: want 201, got %d\n%s", resp.StatusCode, raw)
	}

	var body struct {
		Token struct {
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode TTL response: %v\n%s", err, raw)
	}
	if body.Token.ExpiresAt == "" {
		t.Fatal("expires_at must be non-empty when ttl_minutes is set")
	}
	exp, err := time.Parse(time.RFC3339Nano, body.Token.ExpiresAt)
	if err != nil {
		// Also try plain RFC3339.
		exp, err = time.Parse(time.RFC3339, body.Token.ExpiresAt)
		if err != nil {
			t.Fatalf("parse expires_at %q: %v", body.Token.ExpiresAt, err)
		}
	}
	minExp := before.Add(50 * time.Second)
	maxExp := after.Add(70 * time.Second)
	if exp.Before(minExp) || exp.After(maxExp) {
		t.Errorf("expires_at %v not in [%v, %v]", exp, minExp, maxExp)
	}
}

// TestTokenEndpointsDisabled verifies that all three token endpoints return 409
// auth_disabled when auth is not enabled.
func TestTokenEndpointsDisabled(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil, nil))
	t.Cleanup(srv.Close)

	probes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/auth/tokens", `{"name":"x"}`},
		{http.MethodGet, "/api/v1/auth/tokens", ""},
		{http.MethodDelete, "/api/v1/auth/tokens/tok-0000000000000000", ""},
	}
	for _, p := range probes {
		var bodyReader io.Reader
		if p.body != "" {
			bodyReader = strings.NewReader(p.body)
		}
		req, _ := http.NewRequest(p.method, srv.URL+p.path, bodyReader)
		if p.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", p.method, p.path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("%s %s: want 409, got %d\n%s", p.method, p.path, resp.StatusCode, raw)
			continue
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode error: %v\n%s", err, raw)
		}
		if e.Code != "auth_disabled" {
			t.Errorf("%s %s: code = %q, want auth_disabled", p.method, p.path, e.Code)
		}
	}
}

func TestTokenTTLBoundaries(t *testing.T) {
	srv, _, creds := newAuthServer(t)
	csrf, client := loginAndGetSession(t, srv.URL)
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true}, {"0", true}, {"-1", false}, {"1", true},
		{"153722867", true}, {"153722868", false},
		{"9223372036854775807", false}, {"9223372036854775808", false},
		{"-9223372036854775809", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			payload := `{"name":"bounds"`
			if tc.value != "" {
				payload += `,"ttl_minutes":` + tc.value
			}
			payload += "}"
			before, _ := creds.ListTokens()
			resp := doWithCSRF(t, client, http.MethodPost, srv.URL+"/api/v1/auth/tokens", csrf, strings.NewReader(payload), "application/json")
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			after, _ := creds.ListTokens()
			if !tc.valid {
				if resp.StatusCode != 400 || len(after) != len(before) {
					t.Fatalf("invalid TTL: status=%d token delta=%d body=%s", resp.StatusCode, len(after)-len(before), raw)
				}
				var body struct {
					Code  string `json:"code"`
					Cause string `json:"cause"`
				}
				if err := json.Unmarshal(raw, &body); err != nil || body.Code == "" || body.Cause == "" {
					t.Fatalf("missing typed error: %s", raw)
				}
				if body.Cause == "ttl_invalid" {
					var detail api.Error
					if err := json.Unmarshal(raw, &detail); err != nil {
						t.Fatal(err)
					}
					if len(detail.Remediation) != 1 || detail.Remediation[0].Action != "set_token_ttl" || detail.Remediation[0].Params["max_minutes"] != float64(auth.MaxTokenTTLMinutes) || detail.Remediation[0].Params["min_minutes"] != float64(0) || detail.Remediation[0].Rationale == "" {
						t.Fatalf("missing TTL remediation: %s", raw)
					}
				}
				return
			}
			if resp.StatusCode != 201 || len(after) != len(before)+1 {
				t.Fatalf("valid TTL: %d %s", resp.StatusCode, raw)
			}
			rec := after[len(after)-1]
			if (rec.ExpiresAt == "") != (tc.value == "" || tc.value == "0") {
				t.Fatalf("wrong expiry: %+v", rec)
			}
		})
	}
}

func TestHTTPRevocationPublicationRetry(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	dir := t.TempDir()
	srv, _, creds := newAuthServerInDir(t, dir)
	bootstrap, _, err := creds.CreateToken("bootstrap", testOperator, 0)
	if err != nil {
		t.Fatal(err)
	}
	secret, rec, err := creds.CreateToken("revoked", testOperator, 0)
	if err != nil {
		t.Fatal(err)
	}
	credDir := filepath.Join(dir, "creds")
	if err := os.Chmod(credDir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(credDir, 0700) })
	revoke := func(want int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/auth/tokens/"+rec.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bootstrap)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("revoke status=%d want=%d body=%s", resp.StatusCode, want, raw)
		}
		if want == 500 && !strings.Contains(string(raw), `"cause":"storage_failure"`) {
			t.Fatalf("untyped failure: %s", raw)
		}
	}
	revoke(500)
	revoke(500)
	if err := os.Chmod(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	revoke(200)
	reopened, err := auth.OpenStore(credDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.VerifyToken(secret); err == nil {
		t.Fatal("reopened store accepts revoked token")
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("revoked token service access: %d", resp.StatusCode)
	}
}
