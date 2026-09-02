// ABOUTME: Tests defaultPoweroff's argv by putting a recording systemctl on PATH and calling the real function.
// ABOUTME: Internal test package: defaultPoweroff is unexported and is never reached through PoweroffFunc.
package guest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultPoweroffExecsSystemctlReboot pins the verb the production
// poweroff path passes to systemctl.
//
// Every other guest test overrides Agent.PoweroffFunc, so nothing else in this
// package ever calls defaultPoweroff. The claim it covers is our own wiring,
// not a hardware fact: whether a guest-initiated restart makes Firecracker exit
// is what the live gate's at011_graceful_stop answers, but which verb we ask
// for is a Go function and testable anywhere.
//
// The regression this catches is a reader who decides the name PoweroffFunc and
// the verb "reboot" disagree and "fixes" the argv back to poweroff — which
// returns every graceful stop on this platform to a forced kill, because this
// guest's ACPI tables advertise no S5 and the VMM never exits. See the comment
// on defaultPoweroff.
//
// No seam is added to production code for this: a recording systemctl on PATH
// exercises the real exec.Command, so the assertion is on what the function
// passes to the real API rather than on a fake having been called.
func TestDefaultPoweroffExecsSystemctlReboot(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "argv")

	script := "#!/bin/sh\n" +
		": > '" + argvFile + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + argvFile + "'; done\n"
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}

	// PATH is replaced outright, not prepended to: a real systemctl earlier in
	// the inherited PATH would otherwise reboot the machine running the tests.
	t.Setenv("PATH", binDir)

	defaultPoweroff()

	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("defaultPoweroff did not exec systemctl (no argv recorded): %v", err)
	}
	argv := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(raw) == 0 {
		argv = nil
	}

	want := []string{"reboot"}
	if len(argv) != len(want) {
		t.Fatalf("systemctl argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("systemctl argv = %q, want %q", argv, want)
		}
	}
}
