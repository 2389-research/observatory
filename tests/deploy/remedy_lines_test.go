// ABOUTME: Checks the copy-paste commands the shipped scripts and docs hand an
// ABOUTME: operator, so a remedy line cannot go stale without a test noticing.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shippedFiles are the files a stranger reads or runs during an install. Test
// files and the plan archive are excluded: they record history, not remedies.
func shippedFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range []string{"../../deploy", "../../scripts", "../../images"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || strings.Contains(path, "/dist/") {
				return nil
			}
			out = append(out, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no shipped files; the walk roots are wrong")
	}
	return out
}

// TestNoFileTellsAnOperatorToRunApparmorParser: `apparmor_parser -r` loads a
// profile into the running kernel and writes nothing to disk, so a host that
// followed such a line comes up after its next reboot with no profile and
// `docker run --security-opt apparmor=vmobs-jailer` failing outright. Every
// remedy has to name deploy/install-apparmor.sh, which installs and then loads.
//
// Two shipped files carried the old line for a while after the script existed --
// scripts/vmobs-container's docker-refused-the-profile branch and the profile's
// own header comment. Both looked right to a reader who already knew the
// difference, which is exactly why a test says it instead of a reviewer.
func TestNoFileTellsAnOperatorToRunApparmorParser(t *testing.T) {
	for _, path := range shippedFiles(t) {
		// The one file that legitimately runs it: installing is what it does.
		if filepath.Base(path) == "install-apparmor.sh" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			// Strip comment markers and prose lead-ins: a command a reader would
			// copy is one that starts the runnable part of its line.
			cmd := strings.TrimSpace(line)
			cmd = strings.TrimLeft(cmd, "#")
			cmd = strings.TrimSpace(cmd)
			if idx := strings.LastIndex(cmd, ": "); idx >= 0 {
				cmd = strings.TrimSpace(cmd[idx+2:])
			}
			cmd = strings.TrimPrefix(cmd, "sudo ")
			if strings.HasPrefix(cmd, "apparmor_parser") {
				t.Errorf("%s:%d hands the operator a bare apparmor_parser line:\n    %s\n"+
					"  It loads without installing; the remedy is `sudo sh deploy/install-apparmor.sh`.",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}
