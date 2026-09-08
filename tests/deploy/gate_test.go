// ABOUTME: Checks the acceptance gate runs in a container under the same
// ABOUTME: boundary as the appliance, and that no host installer survives.
package deploy_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	gateScriptPath     = "../../scripts/vmobs-gate"
	gateDockerfilePath = "../../deploy/Dockerfile.gate"
	repoRoot           = "../.."
)

// hostInstaller is the script that installed vmobs onto a bare-metal host: a
// sudoers file, a systemd unit, binaries under /usr/local, and group edits. The
// container replaced every one of those for the product on 2026-09-06, but the
// acceptance gate had been written five days earlier and still named this script
// as its prerequisite -- so running the gate reinstalled host privd underneath
// the container. Deleting the script is the fix; this constant is what the tests
// below hunt for so it cannot come back by reference.
const hostInstaller = "aibox03/setup.sh"

// historicalRecords are dated logs of what was done and when. They describe a
// host install that really happened, so scrubbing the name out of them would be
// rewriting the record rather than fixing the code. Everything else in the tree
// is a live instruction and has to point at the container.
var historicalRecords = []string{
	"PLAN.md",
	"docs/VALIDATION.md",
	"docs/superpowers/plans",
}

// TestNoHostInstallerRemains is the regression that the containerization missed.
// The product moved into the image; the gate did not, so the installer survived
// as the gate's prerequisite and nobody noticed until it clobbered a host.
func TestNoHostInstallerRemains(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot, "scripts", hostInstaller)); err == nil {
		t.Errorf("scripts/%s still exists; the container is the only install path", hostInstaller)
	}

	var offenders []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			// Skip the artifact and history directories wholesale: .git holds
			// every deleted version of the installer, images/dist holds a
			// gigabyte of guest kernel, and web/dist is a build product.
			switch rel {
			case ".git", "images/dist", "web/dist", "node_modules":
				return fs.SkipDir
			}
			if slices.Contains(historicalRecords, rel) {
				return fs.SkipDir
			}
			return nil
		}
		if slices.Contains(historicalRecords, rel) {
			return nil
		}
		// Text only. A binary that happens to contain the byte sequence is not
		// an instruction to anyone.
		switch filepath.Ext(rel) {
		case ".go", ".md", ".sh", ".yaml", ".yml", ".json", ".py", "":
		default:
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil || !strings.Contains(string(body), hostInstaller) {
			return nil
		}
		// This test file names it on purpose.
		if rel == filepath.Join("tests", "deploy", "gate_test.go") {
			return nil
		}
		offenders = append(offenders, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	for _, o := range offenders {
		t.Errorf("%s still tells someone to run scripts/%s; the gate runs in a container now", o, hostInstaller)
	}
}

// TestGateRunsUnderTheSameBoundaryAsTheAppliance: the gate's whole purpose is to
// prove the shipped thing works. A gate container holding capabilities the
// appliance does not would pass on privileges no user will ever have.
func TestGateRunsUnderTheSameBoundaryAsTheAppliance(t *testing.T) {
	svc := loadService(t)

	got := dockerRunFlags(t, gateScriptPath, "--cap-add")
	want := slices.Clone(svc.CapAdd)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("scripts/vmobs-gate --cap-add = %v, compose.yaml grants %v", got, want)
	}

	got = dockerRunFlags(t, gateScriptPath, "--device")
	want = nil
	for _, d := range svc.Devices {
		want = append(want, strings.SplitN(d, ":", 2)[0])
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("scripts/vmobs-gate --device = %v, compose.yaml passes %v", got, want)
	}

	// Both security profiles, or the gate measures a boundary nobody ships.
	opts := strings.Join(dockerRunFlags(t, gateScriptPath, "--security-opt"), " ")
	for _, want := range []string{"apparmor=", "seccomp="} {
		if !strings.Contains(opts, want) {
			t.Errorf("scripts/vmobs-gate passes no %s; --security-opt = %q", want, opts)
		}
	}
	if strings.Contains(opts, "apparmor=unconfined") {
		t.Errorf("scripts/vmobs-gate defaults to apparmor=unconfined; the gate would pass without the confinement the appliance runs under")
	}
}

// TestGateBuildsOnTheApplianceImage: the gate adds a toolchain to the image the
// user installs. Building firecracker, the jailer or the guest artifacts a
// second time would let the gate pass against bytes nobody ships.
func TestGateBuildsOnTheApplianceImage(t *testing.T) {
	raw, err := os.ReadFile(gateDockerfilePath)
	if err != nil {
		t.Fatalf("read %s: %v", gateDockerfilePath, err)
	}
	body := string(raw)

	var froms []string
	for _, line := range strings.Split(body, "\n") {
		if f, ok := strings.CutPrefix(strings.TrimSpace(line), "FROM "); ok {
			froms = append(froms, strings.TrimSpace(f))
		}
	}
	if len(froms) == 0 {
		t.Fatalf("%s declares no FROM", gateDockerfilePath)
	}
	// The last FROM is the stage that ships; earlier ones are sources to copy
	// from (the Go toolchain).
	final := froms[len(froms)-1]
	if !strings.Contains(final, "APPLIANCE_IMAGE") {
		t.Errorf("final FROM is %q, want it parameterised on the appliance image so the gate runs against shipped bytes", final)
	}

	// The pinned artifacts arrive with the appliance image. Fetching them again
	// here is how a gate ends up proving something about a different binary.
	for _, forbidden := range []string{"firecracker.release_url", "fetch-guest-images"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("%s references %q; the appliance image already carries that artifact", gateDockerfilePath, forbidden)
		}
	}
}

// TestGateEvidenceOutlivesTheContainer: the gate publishes one execution record
// per acceptance row, and internal/evidence puts them under $VMOBS_EVIDENCE_ROOT
// -- default <tmpdir>/vmobs-evidence. Inside a `docker run --rm` container that
// default is a path in the container's own filesystem, so every record would be
// deleted at the moment the run that earned it finished. The gate has to hand
// the records a directory that came from the host.
func TestGateEvidenceOutlivesTheContainer(t *testing.T) {
	raw, err := os.ReadFile(gateScriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", gateScriptPath, err)
	}
	body := string(raw)

	if !strings.Contains(body, "VMOBS_EVIDENCE_ROOT") {
		t.Fatalf("%s never sets VMOBS_EVIDENCE_ROOT; records would land in the container's /tmp and die with it", gateScriptPath)
	}

	// The value it sets has to be a mount point, not just any path.
	mounts := dockerRunFlags(t, gateScriptPath, "--volume")
	var dest []string
	for _, m := range mounts {
		parts := strings.Split(m, ":")
		if len(parts) >= 2 {
			dest = append(dest, parts[1])
		}
	}
	envs := dockerRunFlags(t, gateScriptPath, "--env")
	var root string
	for _, e := range envs {
		if v, ok := strings.CutPrefix(strings.Trim(e, `"`), "VMOBS_EVIDENCE_ROOT="); ok {
			root = v
		}
	}
	if root == "" {
		t.Fatalf("%s passes no --env VMOBS_EVIDENCE_ROOT=...; --env = %v", gateScriptPath, envs)
	}
	if !slices.Contains(dest, root) {
		t.Errorf("VMOBS_EVIDENCE_ROOT=%q is not a mounted directory; --volume destinations are %v", root, dest)
	}
}

// TestDockerfilesCopyFromTheBuildContext: .dockerignore was written for the
// appliance image, which needs no tests and no docs, so it excludes tests/
// wholesale. The gate Dockerfile copies one file out of tests/ -- the root
// helper the M0 fixture execs -- and an excluded COPY source is not a parse
// error. It fails minutes into a build, on the machine with the KVM, saying only
// "not found" about a file that is plainly there. Two files have to agree and
// nothing checked that they did.
func TestDockerfilesCopyFromTheBuildContext(t *testing.T) {
	patterns := dockerignorePatterns(t)
	for _, dockerfile := range []string{gateDockerfilePath, "../../deploy/Dockerfile"} {
		for _, src := range contextCopySources(t, dockerfile) {
			if pat, excluded := excludedBy(patterns, src); excluded {
				t.Errorf("%s copies %s, but .dockerignore %q keeps it out of the build context", dockerfile, src, pat)
			}
		}
	}
}

// dockerignorePatterns reads .dockerignore in file order. Docker applies the
// patterns in sequence and the last one that matches a path decides its fate, so
// the order is the meaning.
func dockerignorePatterns(t *testing.T) []string {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".dockerignore"))
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// contextCopySources returns the COPY sources a Dockerfile takes from the build
// context. `COPY --from=<stage>` reads out of an image instead, and
// .dockerignore has nothing to say about those.
func contextCopySources(t *testing.T, dockerfile string) []string {
	raw, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("read %s: %v", dockerfile, err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "COPY ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		var args []string
		fromImage := false
		for _, f := range fields {
			if strings.HasPrefix(f, "--") {
				fromImage = fromImage || strings.HasPrefix(f, "--from=")
				continue
			}
			args = append(args, f)
		}
		// The last argument is the destination; everything before it is a source.
		if fromImage || len(args) < 2 {
			continue
		}
		out = append(out, args[:len(args)-1]...)
	}
	return out
}

// excludedBy answers whether .dockerignore keeps p out of the build context, and
// names the pattern that decided. Every pattern is tried and the last match
// wins, so a negation after a directory exclusion puts one file back -- which is
// how the pinned guest images survive the `images` line.
func excludedBy(patterns []string, p string) (string, bool) {
	p = strings.Trim(p, "/")
	decided, excluded := "", false
	for _, pat := range patterns {
		negated := strings.HasPrefix(pat, "!")
		if !matchesPath(strings.TrimPrefix(pat, "!"), p) {
			continue
		}
		decided, excluded = pat, !negated
	}
	return decided, excluded
}

// matchesPath reports whether a .dockerignore pattern covers a path: either it
// matches the path itself, or it matches one of its parent directories, because
// excluding a directory excludes everything under it.
func matchesPath(pattern, p string) bool {
	pattern = strings.Trim(pattern, "/")
	for cur := p; cur != "." && cur != "/"; cur = filepath.Dir(cur) {
		if ok, err := filepath.Match(pattern, cur); err == nil && ok {
			return true
		}
	}
	return false
}
