// ABOUTME: Runs scripts/fetch-guest-images against a real HTTP server, so an
// ABOUTME: install downloads the pinned guest artifacts instead of building them.
package deploy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fetchScriptPath = "../../scripts/fetch-guest-images"

// The two artifacts the lock pins by digest and this script fetches by URL.
// Bodies are arbitrary; only the digests have to agree with the lock.
var fetchBodies = map[string]string{
	"vmlinux":     "not really a kernel, but it hashes like one\n",
	"rootfs.ext4": "not really a root image either\n",
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// serveArtifacts answers each artifact name with its body. A request for a name
// it does not know is a 404, so a script that invents a URL fails loudly.
func serveArtifacts(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeLock puts a runtime.lock.json in dir carrying the given URLs and digests.
// It is the real schema value, because Load rejects any other.
func writeLock(t *testing.T, dir, kernelURL, kernelSHA, rootURL, rootSHA string) string {
	t.Helper()
	lock := map[string]any{
		"schema": "vmobs.runtime_lock.v1",
		"guest_kernel": map[string]any{
			"version":        "6.1.186",
			"vmlinux_url":    kernelURL,
			"vmlinux_sha256": kernelSHA,
			"vmlinux_path":   "images/dist/vmlinux",
		},
		"root_image": map[string]any{
			"url":    rootURL,
			"sha256": rootSHA,
			"path":   "images/dist/rootfs.ext4",
		},
	}
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	path := filepath.Join(dir, "runtime.lock.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	return path
}

// runFetch invokes the real script against a throwaway root and lock.
func runFetch(t *testing.T, lockPath, root string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", fetchScriptPath, "--lock", lockPath, "--root", root)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestFetchDownloadsAndVerifies is the whole point: an installer should not
// compile a 6.1 kernel to run this. The lock already pins both digests, so
// fetching is verified by construction -- what was missing was somewhere to
// fetch from.
func TestFetchDownloadsAndVerifies(t *testing.T) {
	srv := serveArtifacts(t, fetchBodies)
	root := t.TempDir()
	lockPath := writeLock(t, root,
		srv.URL+"/vmlinux", sha256Hex(fetchBodies["vmlinux"]),
		srv.URL+"/rootfs.ext4", sha256Hex(fetchBodies["rootfs.ext4"]))

	out, err := runFetch(t, lockPath, root)
	if err != nil {
		t.Fatalf("fetch failed: %v\n%s", err, out)
	}

	for name, want := range map[string]string{
		"images/dist/vmlinux":     fetchBodies["vmlinux"],
		"images/dist/rootfs.ext4": fetchBodies["rootfs.ext4"],
	} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v\n%s", name, err, out)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestFetchRefusesAMismatchedDigest: a fetched artifact that does not match its
// pin is the one failure that must never be survivable. The bad bytes must also
// not be left at the destination -- a later run that trusts an existing file
// would then adopt them, and the appliance would boot a kernel nobody pinned.
func TestFetchRefusesAMismatchedDigest(t *testing.T) {
	srv := serveArtifacts(t, fetchBodies)
	root := t.TempDir()
	const wrong = "0000000000000000000000000000000000000000000000000000000000000000"
	lockPath := writeLock(t, root,
		srv.URL+"/vmlinux", wrong,
		srv.URL+"/rootfs.ext4", sha256Hex(fetchBodies["rootfs.ext4"]))

	out, err := runFetch(t, lockPath, root)
	if err == nil {
		t.Fatalf("fetch succeeded with a mismatched digest:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(root, "images/dist/vmlinux")); statErr == nil {
		t.Errorf("the unverified file was left at images/dist/vmlinux; a later run would trust it")
	}
	// The message has to carry both digests, or the operator cannot tell a
	// corrupted download from a lock that was repinned without republishing.
	if !strings.Contains(out, wrong) {
		t.Errorf("refusal never prints the pinned digest:\n%s", out)
	}
	if !strings.Contains(out, sha256Hex(fetchBodies["vmlinux"])) {
		t.Errorf("refusal never prints the digest it actually got:\n%s", out)
	}
}

// TestFetchKeepsAFileThatAlreadyMatches makes the script idempotent, which is
// what lets `up` call it on every start. Proven by serving different bytes than
// the ones on disk: if it re-downloaded, the file would change.
func TestFetchKeepsAFileThatAlreadyMatches(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "images/dist"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	onDisk := fetchBodies["vmlinux"]
	if err := os.WriteFile(filepath.Join(root, "images/dist/vmlinux"), []byte(onDisk), 0o644); err != nil {
		t.Fatalf("seed vmlinux: %v", err)
	}

	srv := serveArtifacts(t, map[string]string{
		"vmlinux":     "different bytes entirely\n",
		"rootfs.ext4": fetchBodies["rootfs.ext4"],
	})
	lockPath := writeLock(t, root,
		srv.URL+"/vmlinux", sha256Hex(onDisk),
		srv.URL+"/rootfs.ext4", sha256Hex(fetchBodies["rootfs.ext4"]))

	out, err := runFetch(t, lockPath, root)
	if err != nil {
		t.Fatalf("fetch failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(root, "images/dist/vmlinux"))
	if err != nil {
		t.Fatalf("read vmlinux: %v", err)
	}
	if string(got) != onDisk {
		t.Errorf("vmlinux was re-downloaded over a file that already matched its pin")
	}
}

// TestFetchNamesTheBuildScriptWhenNothingIsPublished: until the artifacts are
// published somewhere, the lock carries no URL. That is not an error in the
// lock -- it is the honest state of a repo that has never cut a release -- so
// the refusal has to hand the operator the other way to get the file.
func TestFetchNamesTheBuildScriptWhenNothingIsPublished(t *testing.T) {
	srv := serveArtifacts(t, fetchBodies)
	root := t.TempDir()
	lockPath := writeLock(t, root,
		"", sha256Hex(fetchBodies["vmlinux"]),
		srv.URL+"/rootfs.ext4", sha256Hex(fetchBodies["rootfs.ext4"]))

	out, err := runFetch(t, lockPath, root)
	if err == nil {
		t.Fatalf("fetch succeeded with no URL pinned:\n%s", out)
	}
	if !strings.Contains(out, "images/build-all.sh") {
		t.Errorf("refusal does not name images/build-all.sh; the operator is told what is missing but not how to make it:\n%s", out)
	}
}
