// ABOUTME: Checks the AppArmor profile is installed to survive a reboot, and
// ABOUTME: that start refuses when the host's copy is missing or out of date.
package deploy_test

import (
	"strings"
	"testing"
)

const (
	installScriptPath = "../../deploy/install-apparmor.sh"
	// Where AppArmor looks at boot. A profile loaded with apparmor_parser and
	// nothing else lives only in the running kernel.
	profileInstallDir = "/etc/apparmor.d/"
)

// TestInstallScriptPutsTheProfileWhereBootLooks is the whole point of the
// script. `apparmor_parser -r deploy/apparmor/vmobs-jailer` loads a profile into
// the running kernel and leaves nothing behind, so the next reboot has no
// vmobs-jailer and `docker run --security-opt apparmor=vmobs-jailer` fails
// outright -- the appliance does not come up until someone remembers the
// command. Measured 2026-09-06 on aibox03: the profile had been loaded five
// times that day and /etc/apparmor.d/vmobs-jailer did not exist.
func TestInstallScriptPutsTheProfileWhereBootLooks(t *testing.T) {
	s := readFile(t, installScriptPath)

	if !strings.Contains(s, profileInstallDir) {
		t.Errorf("%s never writes to %s; a profile it only parses is gone after a reboot",
			installScriptPath, profileInstallDir)
	}
	if !strings.Contains(s, "apparmor_parser") {
		t.Errorf("%s installs the file but never loads it; the running kernel would keep the old profile until a reboot",
			installScriptPath)
	}
	// Installing after loading would load whatever was there before. The order
	// is read from the code alone: the comments above it name both steps, in the
	// order they are explained rather than the order they run.
	code := shellCode(s)
	install := strings.Index(code, profileInstallDir)
	parse := strings.Index(code, "apparmor_parser")
	if install < 0 || parse < 0 {
		t.Fatalf("%s: install at %d, load at %d in its executable lines; both have to be there",
			installScriptPath, install, parse)
	}
	if install > parse {
		t.Errorf("%s loads the profile before installing it; the load would read the previous copy",
			installScriptPath)
	}
}

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
// the appliance and the acceptance gate. Both hand docker the same profile, so
// both owe the operator the same refusals when the host's copy is wrong.
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

// TestStartChecksTheInstalledProfileMatchesTheRepo: a stale profile is the
// expensive failure, because it is silent. docker accepts any loaded profile by
// name, so the container starts, privd's probe passes whatever the old rules
// allowed, and the mismatch surfaces later as a denial in the middle of a launch.
// That cost several rebuild-and-restart cycles on 2026-09-06.
//
// The check compares the repo's profile with the copy in /etc/apparmor.d,
// because that is all an operator can read: /sys/kernel/security/apparmor/profiles
// is 0444 root-only, so what the kernel actually holds is not observable here.
// The message has to say which of the two it compared.
func TestStartChecksTheInstalledProfileMatchesTheRepo(t *testing.T) {
	for _, path := range operatorScripts {
		s := readShellUnit(t, path)

		if !strings.Contains(s, profileInstallDir) {
			t.Errorf("%s never looks at %s; a stale loaded profile starts fine and fails mid-launch",
				path, profileInstallDir)
			continue
		}
		if !strings.Contains(s, "install-apparmor.sh") {
			t.Errorf("%s does not name deploy/install-apparmor.sh; the refusal has to carry the command that fixes it",
				path)
		}
	}
}

// TestStartSaysSoWhenTheHostHasNoAppArmor: preflight_host checked that the
// profile file was in the repo, which says nothing about the host. On a host
// without AppArmor that check passes and docker then refuses with its own error
// about a profile it cannot find -- which reads like a missing profile rather
// than a kernel that has no AppArmor at all.
func TestStartSaysSoWhenTheHostHasNoAppArmor(t *testing.T) {
	for _, path := range operatorScripts {
		s := readShellUnit(t, path)

		const enabledFlag = "/sys/module/apparmor/parameters/enabled"
		if !strings.Contains(s, enabledFlag) {
			t.Errorf("%s never reads %s; it cannot tell a host without AppArmor from an unloaded profile",
				path, enabledFlag)
		}
		// The escape hatch has to be named, or the only advice is "install AppArmor".
		if !strings.Contains(s, "VMOBS_APPARMOR_PROFILE=unconfined") {
			t.Errorf("%s does not name VMOBS_APPARMOR_PROFILE=unconfined; an operator on a host without AppArmor is left with no way to run at all",
				path)
		}
	}
}
