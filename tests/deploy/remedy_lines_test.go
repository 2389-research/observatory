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
// compose.yaml is named on its own because it is the one such file at the
// repository root, and it is the first one a stranger opens.
func shippedFiles(t *testing.T) []string {
	t.Helper()
	out := []string{"../../compose.yaml"}
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

// The Compose service owns policy loading. Operator remedies must use it so
// they work with the same image and security boundary as normal startup.
func TestNoFileTellsAnOperatorToRunApparmorParser(t *testing.T) {
	for _, path := range shippedFiles(t) {
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
					"  Use the Compose apparmor service instead of a host command.",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestShippedFilesDoNotRequireHostPolicyInstallation(t *testing.T) {
	for _, path := range shippedFiles(t) {
		if strings.Contains(readFile(t, path), "install-apparmor.sh") {
			t.Errorf("%s still references the removed host policy installer", path)
		}
	}
}
