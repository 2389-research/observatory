// ABOUTME: Serves the embedded fleet page under /ui/ and redirects the site root to it.
// ABOUTME: Only /ui/ is claimed; every other unknown path keeps the API's typed 404.
package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/2389-research/observatory/web"
)

// uiPrefix is the single path the UI owns. Keeping it to one prefix is what
// lets an unknown /api/v1/... path still reach notFound with typed JSON (P-07).
const uiPrefix = "/ui/"

// mountUI attaches the embedded page. The handler serves a real file when the
// path names one and the shell otherwise, so a client-side deep link boots the
// app instead of 404ing — with one exception: a miss under assets/ is a genuine
// 404, because answering an asset request with HTML hides the real fault.
func mountUI(mux *http.ServeMux) {
	assets := web.Assets()
	files := http.StripPrefix(uiPrefix, http.FileServer(http.FS(assets)))

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, uiPrefix, http.StatusFound)
	})

	mux.HandleFunc(uiPrefix, func(w http.ResponseWriter, r *http.Request) {
		rel := path.Clean(strings.TrimPrefix(r.URL.Path, uiPrefix))
		if rel == "." || rel == "/" {
			serveShell(w, r, assets)
			return
		}
		if _, err := fs.Stat(assets, rel); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(rel, "assets/") {
			http.NotFound(w, r)
			return
		}
		serveShell(w, r, assets)
	})
}

func serveShell(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	body, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "the embedded UI is missing its index",
			Retryable: false,
			Cause:     "ui_not_built",
			Remediation: []Remediation{{
				Action:    "rebuild the daemon after running scripts/build-web",
				Rationale: "web/dist is embedded at build time",
			}},
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The rest of the policy travels with the page, in index.html's meta tag,
	// so a dist/ served by anything else keeps it. frame-ancestors cannot: a
	// browser ignores it in a meta tag, and an unframeable shell is what keeps
	// a guest terminal from being clicked through an invisible iframe (§8.4).
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	// The shell is content-addressed only in the assets it names, so it must
	// never be cached: a stale shell points at asset hashes that no longer exist.
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
