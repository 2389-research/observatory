// ABOUTME: Checks the shipped config, template and Dockerfile describe one host:
// ABOUTME: every path the config names is a path the image actually creates.
package deploy_test

import (
	"os"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/config"
	vmruntime "github.com/2389-research/observatory/internal/runtime"
)

const (
	configPath     = "../../deploy/config.yaml"
	dockerfilePath = "../../deploy/Dockerfile"
	entrypointPath = "../../deploy/entrypoint.sh"
	templatesDir   = "../../deploy/templates"
)

// TestShippedConfigLoads runs the image's config through the same strict loader
// the daemon uses. The container has no other chance to find a typo: an unknown
// field or an out-of-range bound is a container that starts and immediately
// exits, with the reason inside a log nobody is watching yet.
func TestShippedConfigLoads(t *testing.T) {
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", configPath, err)
	}

	// loopback_only is what makes require_authentication: false legal, and what
	// makes --network host the right run mode. Either half changing alone turns
	// the shipped appliance into an unauthenticated API on a routable address.
	if cfg.Server.Mode != "loopback_only" {
		t.Errorf("server.mode = %q; deploy/README.md documents --network host on the strength of loopback_only", cfg.Server.Mode)
	}
	if !strings.HasPrefix(cfg.Server.Listen, "127.0.0.1:") {
		t.Errorf("server.listen = %q, want a 127.0.0.1 address", cfg.Server.Listen)
	}
	if cfg.Runtime.Mode != "firecracker" {
		t.Errorf("runtime.mode = %q, want firecracker; the appliance never serves the fake runtime", cfg.Runtime.Mode)
	}
}

// TestConfigPathsAreImagePaths: every path the config names has to be somewhere
// the image puts something. A config pointing at a directory no layer creates
// fails at the first launch, not at start.
func TestConfigPathsAreImagePaths(t *testing.T) {
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", configPath, err)
	}
	dockerfile := readFile(t, dockerfilePath)
	entrypoint := readFile(t, entrypointPath)

	for _, c := range []struct {
		field, value, mustAppearIn, where string
	}{
		{"paths.runtime_lock", cfg.Paths.RuntimeLock, dockerfile, dockerfilePath},
		{"runtime.lock_file", cfg.Runtime.LockFile, dockerfile, dockerfilePath},
		{"paths.approved_templates", cfg.Paths.ApprovedTemplates, dockerfile, dockerfilePath},
		{"paths.state", cfg.Paths.State, dockerfile, dockerfilePath},
		{"paths.runtime", cfg.Paths.Runtime, dockerfile, dockerfilePath},
		{"paths.privileged_socket", cfg.Paths.PrivilegedSocket, entrypoint, entrypointPath},
	} {
		if c.value == "" {
			t.Errorf("%s is empty", c.field)
			continue
		}
		if !strings.Contains(c.mustAppearIn, c.value) {
			t.Errorf("%s = %q, but %s never mentions it", c.field, c.value, c.where)
		}
	}

	// The jail gid is the group firecracker binds each VM's v.sock as, and the
	// daemon has to traverse it. The Dockerfile creates exactly this gid.
	if !strings.Contains(dockerfile, "--gid 36000") || cfg.Runtime.JailGID != 36000 {
		t.Errorf("runtime.jail_gid = %d, but the image creates the group the Dockerfile names; they must agree",
			cfg.Runtime.JailGID)
	}
	// CIDs 0-2 are reserved by the vsock spec, and privd refuses a CID below 3.
	if cfg.Runtime.CIDBase < 3 {
		t.Errorf("runtime.cid_base = %d; privd refuses a CID below 3", cfg.Runtime.CIDBase)
	}
}

// TestShippedTemplateLoads: the approved templates baked into the image go
// through the strict loader that rejects retired keys. Getting this wrong ships
// an appliance whose only template is unusable.
func TestShippedTemplateLoads(t *testing.T) {
	templates, err := vmruntime.LoadTemplates(templatesDir)
	if err != nil {
		t.Fatalf("LoadTemplates(%s): %v", templatesDir, err)
	}
	if len(templates) == 0 {
		t.Fatal("the image ships no approved template; nothing could be launched")
	}
	for id, tpl := range templates {
		if id == "" {
			t.Errorf("template in %s has an empty template_id", templatesDir)
		}
		if len(tpl.GuestPrivilegeProfiles) == 0 {
			t.Errorf("template %q declares no guest_privilege_profiles", id)
		}
		if tpl.Digest == "" {
			t.Errorf("template %q has no digest", id)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
