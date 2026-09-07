// ABOUTME: Checks the committed dist the daemon embeds is a production build
// ABOUTME: and carries no path from whichever machine happened to build it.
package web

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

// bundles returns every JavaScript asset the daemon will serve, by name and
// content. It fails on an empty result: every check below is a search for
// something that must be absent, so a walk that found no bundles would pass
// them all while proving nothing.
func bundles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(Assets(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".js" {
			return err
		}
		b, err := fs.ReadFile(Assets(), p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded dist: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the embedded dist contains no .js bundle; web/dist is missing or the embed pattern stopped matching")
	}
	return out
}

// TestTheEmbeddedBundleIsAProductionBuild: `vite build` picks its mode from
// NODE_ENV when that is set, so a shell exporting NODE_ENV=development produces
// a React *development* bundle and the gate's "web dist current" check happily
// calls it current -- it only asks whether a rebuild moves the bytes, and on that
// machine it does not.
//
// Measured 2026-09-07: the committed index chunk was 452,554 bytes against
// 232,268 for the same source built with NODE_ENV cleared. The extra 220 KB is
// React's development build, which validates props on every element and
// allocates an Error per element to carry a stack trace.
//
// web/package.json pins NODE_ENV=production in the build script so the committed
// artifact no longer depends on the environment of whoever ran it.
func TestTheEmbeddedBundleIsAProductionBuild(t *testing.T) {
	for name, body := range bundles(t) {
		for _, marker := range []string{"jsxDEV", "react-jsx-dev-runtime", "react-stack-top-frame"} {
			if strings.Contains(body, marker) {
				t.Errorf("%s contains %q: this is a development build. Rebuild with scripts/build-web", name, marker)
			}
		}
	}
}

// TestTheEmbeddedBundleNamesNoBuildMachine: the development JSX transform stamps
// every element with the absolute path of its source file, so a dev build serves
// the build machine's directory layout to every browser that loads the page.
// Seventeen of them shipped before this test existed.
func TestTheEmbeddedBundleNamesNoBuildMachine(t *testing.T) {
	// An absolute path ending in a source extension: what the transform emits,
	// and specific enough not to match a URL or a served route.
	buildPath := regexp.MustCompile(`(/Users/|/home/)[^"'` + "`" + `\s]*\.(tsx|ts|jsx)\b`)
	for name, body := range bundles(t) {
		if m := buildPath.FindString(body); m != "" {
			t.Errorf("%s names a path from the machine that built it: %s", name, m)
		}
	}
}
