// ABOUTME: Checks startup loads the bundled AppArmor policy through Compose.
// ABOUTME: Host configuration files are neither prerequisites nor install targets.
package deploy_test

import (
	"os"
	"strings"
	"testing"
)

// shellCode drops comment lines so an assertion about what a script does is not
// answered by what its comments say.
func shellCode(s string) string {
	var code []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		code = append(code, line)
	}
	return strings.Join(code, "\n")
}

// operatorScripts are the two commands an operator runs to start a container:
// the appliance and the acceptance gate. Both use the Compose policy loader.
var operatorScripts = []string{
	"../../scripts/vmobs-container",
	"../../scripts/vmobs-gate",
}

// readShellUnit returns a script together with the text of the libraries it
// sources, because that is what runs. Asserting against the entry point alone
// would call a check missing the moment it moved into scripts/lib/, and asserting
// against the library alone would miss a script that never sources it.
func readShellUnit(t *testing.T, path string) string {
	t.Helper()
	body := readFile(t, path)
	var parts []string
	parts = append(parts, body)
	for _, line := range strings.Split(shellCode(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || (fields[0] != "." && fields[0] != "source") {
			continue
		}
		// The only form these scripts use: . "$REPO/scripts/lib/<name>"
		ref := strings.Trim(fields[1], `"`)
		rel, ok := strings.CutPrefix(ref, "$REPO/")
		if !ok {
			t.Fatalf("%s sources %q, which this test cannot resolve", path, ref)
		}
		parts = append(parts, readFile(t, "../../"+rel))
	}
	if len(parts) == 1 {
		t.Fatalf("%s sources nothing; the shared preflight lives in scripts/lib/", path)
	}
	return strings.Join(parts, "\n")
}

// The image and kernel are the sources of policy; an installed host file can
// survive independently and must never be used to decide whether startup is safe.
func TestStartupUsesComposePolicyLoader(t *testing.T) {
	for _, path := range operatorScripts {
		s := shellCode(readShellUnit(t, path))
		const invoke = `VMOBS_IMAGE="$1" docker compose -f "$REPO/compose.yaml" run --rm --no-deps apparmor`
		if !strings.Contains(s, invoke) {
			t.Errorf("%s does not invoke the shared Compose loader with the selected image", path)
		}
		for _, forbidden := range []string{"/etc/apparmor.d/", "cmp -s", "apparmor_parser", "install-apparmor.sh"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("%s still manages host policy directly with %q", path, forbidden)
			}
		}
		body := shellCode(readFile(t, path))
		image := "$tag"
		if path == gateScriptPath {
			image = "$APPLIANCE"
		}
		load := strings.Index(body, `load_apparmor "`+image+`"`)
		run := strings.Index(body, "docker run")
		if load < 0 || run < load {
			t.Errorf("%s must load policy from %s before starting the container", path, image)
		}
	}
}

func TestNoAppArmorHostInstallerRemains(t *testing.T) {
	if _, err := os.Stat("../../deploy/install-apparmor.sh"); !os.IsNotExist(err) {
		t.Fatalf("host policy installer must be absent, stat returned %v", err)
	}
}

func TestStartSaysSoWhenTheHostHasNoAppArmor(t *testing.T) {
	for _, path := range operatorScripts {
		s := readShellUnit(t, path)
		if !strings.Contains(s, "/sys/module/apparmor/parameters/enabled") {
			t.Errorf("%s does not distinguish a host without AppArmor", path)
		}
		if !strings.Contains(s, "VMOBS_APPARMOR_PROFILE=unconfined") {
			t.Errorf("%s omits the existing explicit unconfined override", path)
		}
	}
}
