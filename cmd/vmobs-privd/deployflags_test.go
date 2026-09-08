// ABOUTME: Parses the vmobs-privd argv out of deploy/entrypoint.sh and runs it
// ABOUTME: through the real parseFlags, so an invented flag fails here not in prod.
package main

import (
	"os"
	"strings"
	"testing"
)

// TestEntrypointArgvParses guards the one seam a container build cannot check
// for itself: the entrypoint writes privd's command line as text, and nothing
// reads it until a container is already running. A flag renamed here and not
// there produces "flag provided but not defined" at container start, several
// minutes and one image build after the mistake.
func TestEntrypointArgvParses(t *testing.T) {
	argv := entrypointPrivdArgv(t)

	flags, err := parseFlags(argv)
	if err != nil {
		t.Fatalf("deploy/entrypoint.sh runs vmobs-privd with %v, which this binary rejects: %v", argv, err)
	}

	// The values the image lays down. Each is a path the Dockerfile creates or a
	// uid it adds; a mismatch is a container that starts and then cannot serve.
	for _, want := range []struct {
		name string
		got  string
		exp  string
	}{
		{"--socket", flags.socket, "/run/vmobs/privd.sock"},
		{"--ledger-dir", flags.ledgerDir, "/srv/vmobs/privd"},
		{"--stage-root", flags.stageRoot, "/srv/vmobs/stage"},
		{"--jail-base", flags.jailBase, "/srv/vmobs/jail"},
		{"--firecracker", flags.firecracker, "/usr/local/bin/firecracker"},
		{"--jailer", flags.jailer, "/usr/local/bin/jailer"},
	} {
		if want.got != want.exp {
			t.Errorf("entrypoint %s = %q, want %q", want.name, want.got, want.exp)
		}
	}
	if flags.allowedUID != 2389 || flags.allowedGID != 2389 {
		t.Errorf("entrypoint allowed uid/gid = %d/%d, want 2389/2389 (the vmobs user the Dockerfile creates)",
			flags.allowedUID, flags.allowedGID)
	}
}

// entrypointPrivdArgv extracts the arguments of the vmobs-privd invocation from
// the entrypoint script, resolving the handful of NAME=value assignments the
// script uses. It is not a shell; it understands exactly the two constructs the
// entrypoint actually uses, and fails loudly on anything else.
func entrypointPrivdArgv(t *testing.T) []string {
	t.Helper()
	const path = "../../deploy/entrypoint.sh"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(raw), "\n")

	vars := map[string]string{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		name, value, ok := strings.Cut(trimmed, "=")
		if !ok || strings.ContainsAny(name, " \t$\"'(){}[]#") || name == "" {
			continue
		}
		if _, taken := vars[name]; !taken {
			vars[name] = strings.Trim(value, `"'`)
		}
	}

	start := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "/usr/local/sbin/vmobs-privd") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s does not run /usr/local/sbin/vmobs-privd", path)
	}

	var fields []string
	for i := start; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		continued := strings.HasSuffix(line, `\`)
		line = strings.TrimSuffix(line, `\`)
		for _, f := range strings.Fields(line) {
			f = strings.Trim(f, `"'`)
			switch {
			case f == "&" || strings.HasSuffix(f, "vmobs-privd"):
				continue
			case strings.HasPrefix(f, "$"):
				name := strings.Trim(strings.TrimPrefix(f, "$"), "{}")
				v, ok := vars[name]
				if !ok {
					t.Fatalf("%s uses $%s in the vmobs-privd argv but never assigns it", path, name)
				}
				f = v
			}
			fields = append(fields, f)
		}
		if !continued {
			break
		}
	}
	if len(fields) == 0 {
		t.Fatalf("%s: no arguments found for vmobs-privd", path)
	}
	return fields
}
