// ABOUTME: Checks compose.yaml runs the container under the same boundary
// ABOUTME: scripts/vmobs-container does: same caps, devices, profiles, mounts.
package deploy_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	composePath   = "../../compose.yaml"
	containerPath = "../../scripts/vmobs-container"
)

// composeService is the subset of the compose schema these checks read.
type composeService struct {
	Image       string   `yaml:"image"`
	Init        *bool    `yaml:"init"`
	NetworkMode string   `yaml:"network_mode"`
	PIDMode     string   `yaml:"pid"`
	CapAdd      []string `yaml:"cap_add"`
	Devices     []string `yaml:"devices"`
	SecurityOpt []string `yaml:"security_opt"`
	Tmpfs       []string `yaml:"tmpfs"`
	Volumes     []string `yaml:"volumes"`
	Restart     string   `yaml:"restart"`
}

// loadService returns the appliance service, independently of setup services.
func loadService(t *testing.T) composeService {
	t.Helper()
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	var c struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", composePath, err)
	}
	node, ok := c.Services["vmobs"]
	if !ok {
		t.Fatal("compose.yaml has no vmobs service")
	}
	var svc composeService
	if err := node.Decode(&svc); err != nil {
		t.Fatalf("decode vmobs service: %v", err)
	}
	return svc
}

// dockerRunFlags pulls the values of one repeated flag out of the `docker run`
// invocation in a shell script. It fails rather than returning an empty set: a
// scan that stopped matching would otherwise turn every drift check below into a
// comparison of nothing against nothing.
//
// The block is the `docker run` line plus every line the backslash
// continuations carry it onto, so it ends where the command does regardless of
// what each script writes afterwards.
func dockerRunFlags(t *testing.T, path, flag string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, line := range lines {
		// Comments talk about `docker run` too, and a comment carries no
		// continuation -- starting there would make the block one line long and
		// every check below a comparison of nothing against nothing.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "docker run") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s contains no `docker run`; this test cannot see what it passes", path)
	}
	block := []string{}
	for i := start; i < len(lines); i++ {
		block = append(block, lines[i])
		if !strings.HasSuffix(strings.TrimRight(lines[i], " \t"), "\\") {
			break
		}
	}

	re := regexp.MustCompile(regexp.QuoteMeta(flag) + ` +"?([^"\\\n]+)"?`)
	var found []string
	for _, m := range re.FindAllStringSubmatch(strings.Join(block, "\n"), -1) {
		found = append(found, strings.TrimSpace(m[1]))
	}
	if len(found) == 0 {
		t.Fatalf("%s: found no %s in the docker run block", path, flag)
	}
	return found
}

// TestComposeGrantsTheSameCapabilities: the two ways to start this container have
// to agree, or `docker compose up` runs under a boundary nobody measured.
func TestComposeGrantsTheSameCapabilities(t *testing.T) {
	want := dockerRunFlags(t, containerPath, "--cap-add")
	got := loadService(t).CapAdd
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("cap_add = %v, scripts/vmobs-container passes %v", got, want)
	}
}

// TestComposePassesTheSameDevices: /dev/kvm and /dev/net/tun. Compose writes a
// device as source:target, so a bare path means both.
func TestComposePassesTheSameDevices(t *testing.T) {
	want := dockerRunFlags(t, containerPath, "--device")
	var got []string
	for _, d := range loadService(t).Devices {
		got = append(got, strings.SplitN(d, ":", 2)[0])
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("devices = %v, scripts/vmobs-container passes %v", got, want)
	}
}

// TestComposeDefaultsToTheConfinedProfile: the boundary docs/design/container-
// boundary.md §9 decided to build. `unconfined` is reachable by setting
// VMOBS_APPARMOR_PROFILE, and a default that skipped the profile would hand every
// third party a container with CAP_SYS_ADMIN and no mount confinement.
func TestComposeDefaultsToTheConfinedProfile(t *testing.T) {
	opts := loadService(t).SecurityOpt

	const wantAppArmor = "apparmor=${VMOBS_APPARMOR_PROFILE:-vmobs-jailer}"
	if !slices.Contains(opts, wantAppArmor) {
		t.Errorf("security_opt = %v, want it to contain %q", opts, wantAppArmor)
	}
	for _, opt := range opts {
		if opt == "apparmor=unconfined" {
			t.Errorf("compose.yaml ships %q; the shipped default is the confined profile", opt)
		}
	}
}

// TestComposeUsesTheSameSeccompProfile: a path, not a name -- compose resolves it
// against the project directory and the daemon applies the file. Measured with
// docker 29.6.1: a profile denying chmod produced EPERM inside the container.
func TestComposeUsesTheSameSeccompProfile(t *testing.T) {
	var got string
	for _, opt := range loadService(t).SecurityOpt {
		if after, ok := strings.CutPrefix(opt, "seccomp="); ok {
			got = after
		}
	}
	if got == "" {
		t.Fatalf("compose.yaml passes no seccomp profile")
	}
	if _, err := os.Stat("../../" + strings.TrimPrefix(got, "./")); err != nil {
		t.Errorf("seccomp=%s does not resolve to a file in the repo: %v", got, err)
	}
	const want = "./deploy/seccomp/vmobs-jailer.json"
	if got != want {
		t.Errorf("seccomp = %q, want %q -- the same file scripts/vmobs-container passes", got, want)
	}
}

// TestComposeMountsTheSameState: both volumes, and /run as a tmpfs. privd binds
// its socket under /run/vmobs, and the image creates that directory in a layer --
// without the tmpfs the socket would persist into the image's own filesystem.
func TestComposeMountsTheSameState(t *testing.T) {
	svc := loadService(t)

	var targets []string
	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			t.Errorf("volume %q has no target", v)
			continue
		}
		targets = append(targets, parts[1])
	}
	slices.Sort(targets)
	if want := []string{"/srv/vmobs", "/var/lib/vmobs"}; !slices.Equal(targets, want) {
		t.Errorf("volume targets = %v, want %v", targets, want)
	}

	if len(svc.Tmpfs) != 1 || !strings.HasPrefix(svc.Tmpfs[0], "/run:") {
		t.Errorf("tmpfs = %v, want a single /run entry", svc.Tmpfs)
	}
}

// Host PID 1 reaps daemonized VMMs; host networking exposes the loopback API.
func TestComposeReapsAndSharesTheHostNetwork(t *testing.T) {
	svc := loadService(t)
	if svc.Init != nil && *svc.Init {
		t.Error("init must be absent or false: host PID 1 reaps VMMs")
	}
	if svc.NetworkMode != "host" {
		t.Errorf("network_mode = %q, want \"host\" -- the API binds loopback", svc.NetworkMode)
	}
	if svc.Restart != "no" {
		t.Errorf("restart = %q, want \"no\"", svc.Restart)
	}
}

// Persistent process ownership must name the same PID namespace after restart.
func TestComposeUsesStableProcessIdentities(t *testing.T) {
	if got := loadService(t).PIDMode; got != "host" {
		t.Fatalf("pid = %q; persistent ownership requires the host PID namespace", got)
	}
	for _, script := range []string{containerPath, "../../scripts/vmobs-gate"} {
		if got := dockerRunFlags(t, script, "--pid"); !slices.Equal(got, []string{"host"}) {
			t.Errorf("%s PID namespace = %v, want host", script, got)
		}
	}
}

// TestComposeDefaultsToAPullableImage: `docker compose up -d` is the whole
// install, so the image it names when nobody sets VMOBS_IMAGE has to be one a
// stranger's Docker can reach. Docker reads a reference with no dot before the
// first slash as a Docker Hub name -- a bare `vmobs:latest` resolves to
// docker.io/library/vmobs, which is not ours and does not exist. The override
// stays, because a local build still wants it.
func TestComposeDefaultsToAPullableImage(t *testing.T) {
	image := loadService(t).Image

	const prefix = "${VMOBS_IMAGE:-"
	if !strings.HasPrefix(image, prefix) || !strings.HasSuffix(image, "}") {
		t.Fatalf("image = %q, want ${VMOBS_IMAGE:-DEFAULT} so a local build can still override it", image)
	}
	def := strings.TrimSuffix(strings.TrimPrefix(image, prefix), "}")

	host, rest, ok := strings.Cut(def, "/")
	if !ok || !strings.Contains(host, ".") {
		t.Fatalf("default image %q names no registry host; Docker would resolve it against Docker Hub", def)
	}
	if rest == "" {
		t.Fatalf("default image %q names a registry and no repository", def)
	}
	if !strings.Contains(rest, ":") {
		t.Errorf("default image %q names no tag; an install would silently follow whatever :latest became", def)
	}
}
