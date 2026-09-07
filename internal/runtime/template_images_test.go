// ABOUTME: A template manifest may not declare image paths — the kernel and root
// ABOUTME: image come from runtime.lock.json, and a second declaration is a lie.
package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
)

// TestLoadTemplatesRefusesImagePaths: `kernel_image` and `root_image` were
// carried on every template manifest and read by nothing. The jailer stages the
// kernel and rootfs from runtime.lock.json, hash-verified against the pins there
// (internal/jailer/launch.go, doStage), so the manifest's paths were a second
// declaration that could not be right and usually was not — the demo host's
// pointed at /srv/vmobs/images, which is not a directory, and scripts/smoke
// wrote /nonexistent/vmlinuz to make the point. Refusing them keeps one source
// of truth for what a VM boots. Issue 52pj.
func TestLoadTemplatesRefusesImagePaths(t *testing.T) {
	for _, field := range []string{"kernel_image", "root_image"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			manifest := `{
				"template_id": "tmpl-images",
				"description": "carries a retired field",
				"` + field + `": "/srv/vmobs/images/vmlinux",
				"guest_privilege_profiles": ["unprivileged"],
				"sensors": [],
				"protocol_versions": {"guestd": "1"}
			}`
			if err := os.WriteFile(filepath.Join(dir, "tmpl-images.json"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := runtime.LoadTemplates(dir)
			if err == nil {
				t.Fatalf("LoadTemplates accepted a manifest declaring %s", field)
			}
			// The operator has to be told where the images actually come from,
			// or "unknown field" reads as a typo in a field we shipped.
			msg := err.Error()
			if !strings.Contains(msg, field) {
				t.Errorf("error does not name the offending field: %v", err)
			}
			if !strings.Contains(msg, "runtime.lock.json") {
				t.Errorf("error does not say where images come from: %v", err)
			}
		})
	}
}

// TestLoadTemplatesAcceptsAManifestWithoutImagePaths: the shape that replaces it
// still loads and still gets a digest computed from its own bytes.
func TestLoadTemplatesAcceptsAManifestWithoutImagePaths(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
		"template_id": "tmpl-clean",
		"description": "no image paths",
		"guest_privilege_profiles": ["unprivileged"],
		"sensors": ["fanotify"],
		"protocol_versions": {"guestd": "1"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "tmpl-clean.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls, err := runtime.LoadTemplates(dir)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tpl, ok := tpls["tmpl-clean"]
	if !ok {
		t.Fatal("template tmpl-clean not found")
	}
	if !strings.HasPrefix(tpl.Digest, "sha256:") {
		t.Errorf("Digest = %q, want a sha256: prefix", tpl.Digest)
	}
}
