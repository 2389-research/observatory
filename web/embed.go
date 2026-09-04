// ABOUTME: Embeds the built fleet page into the daemon binary so vmobs serves its own UI.
// ABOUTME: dist/ is committed: go build and the acceptance gate must not need a node toolchain.
package web

import (
	"embed"
	"io/fs"
)

// dist holds the Vite build output. `all:` keeps files whose names begin with
// `_` or `.`, which bundlers emit and the default embed pattern would drop.
//
//go:embed all:dist
var dist embed.FS

// Assets returns the built page rooted at its index, ready to mount.
func Assets() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Only reachable if the embed directive above stops matching, which is
		// a build-time fact, not a runtime condition.
		panic("web: dist not embedded: " + err.Error())
	}
	return sub
}
