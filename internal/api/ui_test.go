// ABOUTME: Tests that the built fleet page is served from the daemon: deep links, assets, and
// ABOUTME: the guarantee that mounting a UI never swallows the API's typed 404 (P-07).
package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/auth"
	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

// noRedirect gives a client that reports a 3xx rather than following it, so a
// redirect can be asserted on directly.
func noRedirect(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestUIRootRedirectsToUI(t *testing.T) {
	srv, _ := newServer(t)
	res, err := noRedirect(t).Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get /: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/ui/" {
		t.Fatalf("Location = %q, want /ui/", loc)
	}
}

func TestUIServesTheBuiltShell(t *testing.T) {
	srv, _ := newServer(t)
	res, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `id="root"`) {
		t.Fatalf("body is not the built shell: %.200q", body)
	}
}

func TestUIDeepLinkServesTheShell(t *testing.T) {
	srv, _ := newServer(t)
	// A client-side route the server knows nothing about must still boot the app.
	res, err := http.Get(srv.URL + "/ui/vms/7f3a9c21")
	if err != nil {
		t.Fatalf("get deep link: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `id="root"`) {
		t.Fatalf("deep link did not serve the shell: %.200q", body)
	}
}

func TestUIServesAssetsWithTheirOwnType(t *testing.T) {
	srv, _ := newServer(t)
	// Find the script the shell actually references, rather than guessing a hash.
	res, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	src := between(string(body), `src="`, `"`)
	if src == "" {
		t.Fatalf("no script src in shell: %.300q", body)
	}

	asset, err := http.Get(srv.URL + src)
	if err != nil {
		t.Fatalf("get %s: %v", src, err)
	}
	defer asset.Body.Close()
	if asset.StatusCode != http.StatusOK {
		t.Fatalf("asset status = %d, want 200", asset.StatusCode)
	}
	if ct := asset.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("asset Content-Type = %q, want javascript", ct)
	}
}

func TestUIMissingAssetIsNotTheShell(t *testing.T) {
	srv, _ := newServer(t)
	// An asset path that does not exist must 404, not silently return HTML —
	// a shell served as a .js file is a debugging trap.
	res, err := http.Get(srv.URL + "/ui/assets/nope-00000000.js")
	if err != nil {
		t.Fatalf("get missing asset: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

func TestUnknownAPIPathStillAnswersTypedJSON(t *testing.T) {
	srv, _ := newServer(t)
	res, err := http.Get(srv.URL + "/api/v1/nope")
	if err != nil {
		t.Fatalf("get unknown api path: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	raw, _ := io.ReadAll(res.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, raw)
	}
	if body["cause"] != "route_unknown" {
		t.Fatalf("cause = %v, want route_unknown", body["cause"])
	}
}

func TestUIIsReachableBeforeLogin(t *testing.T) {
	// The shell carries no host data: it must load so the operator can sign in.
	dir := t.TempDir()
	credStore, err := auth.InitStore(filepath.Join(dir, "creds"), "operator", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("init cred store: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{QueueMaxItems: 500, SituationMaxResponseBytes: 65536})
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
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{
		Enabled:        true,
		Creds:          credStore,
		Sessions:       auth.NewSessions(time.Hour),
		CookieSameSite: http.SameSiteStrictMode,
		LoginDelay:     time.Millisecond,
	}, nil, nil))
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}

	res, err := client.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/ unauthenticated: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unauthenticated /ui/ status = %d, want 200", res.StatusCode)
	}

	// The data behind it stays closed.
	api1, err := client.Get(srv.URL + "/api/v1/host/status")
	if err != nil {
		t.Fatalf("get host status unauthenticated: %v", err)
	}
	defer api1.Body.Close()
	if api1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated host status = %d, want 401", api1.StatusCode)
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// A same-site session cookie plus a framed shell is a clickjacked guest shell:
// the operator's clicks land on a terminal they cannot see. §8.4 asks for a
// restrictive CSP, and frame-ancestors is the one directive a <meta> tag in
// index.html cannot express — a browser ignores it there. So it is a header.
func TestUIShellRefusesToBeFramed(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range []string{"/ui/", "/ui/vms/abc"} {
		res, err := noRedirect(t).Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		res.Body.Close()
		if got := res.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
			t.Errorf("%s CSP = %q, want frame-ancestors 'none'", path, got)
		}
	}
}
