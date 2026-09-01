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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
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
	dir := t.TempDir()
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
		Owner:      testOperator,
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

	srv := httptest.NewServer(api.New(st, eng, mgr, ac))
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

	// Wait a moment for the event to land (the handler delays then appends).
	time.Sleep(50 * time.Millisecond)

	// Verify a login_failed event was recorded.
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
		Owner:      testOperator,
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}))
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
	if sessionCookieValue != "" {
		for _, env := range append(createdResult.Events, endedResult.Events...) {
			payload, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(payload), sessionCookieValue) {
				t.Errorf("event payload contains session cookie value: %s", payload)
			}
		}
	}

	// Sanity: events are host_observed.
	for _, env := range createdResult.Events {
		if env.Provenance != events.HostObserved {
			t.Errorf("session_created: provenance = %q, want host_observed", env.Provenance)
		}
	}
}
