// ABOUTME: Checks the image workflow builds what scripts/vmobs-container builds,
// ABOUTME: pins every action it runs, and never pushes from a pull request.
package deploy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const workflowPath = "../../.github/workflows/image.yml"

// workflow is the subset of the Actions schema these checks read. `on` is a
// reserved word in YAML 1.1 -- it parses as the boolean true -- so the trigger
// block is read from the raw text rather than from a struct field.
type workflow struct {
	Name        string            `yaml:"name"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		RunsOn string `yaml:"runs-on"`
		Steps  []struct {
			Name string            `yaml:"name"`
			Uses string            `yaml:"uses"`
			If   string            `yaml:"if"`
			Run  string            `yaml:"run"`
			ID   string            `yaml:"id"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) (workflow, string) {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", workflowPath, err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatalf("parse %s: %v", workflowPath, err)
	}
	if len(w.Jobs) == 0 {
		t.Fatalf("%s declares no jobs", workflowPath)
	}
	return w, string(raw)
}

// steps flattens every step in the workflow. The checks below are properties of
// the workflow as a whole, not of one job, so splitting them by job would only
// make a later job split break tests that should not care.
func steps(w workflow) []struct {
	Name string
	Uses string
	If   string
	Run  string
	ID   string
	With map[string]string
} {
	var out []struct {
		Name string
		Uses string
		If   string
		Run  string
		ID   string
		With map[string]string
	}
	for _, job := range w.Jobs {
		for _, s := range job.Steps {
			out = append(out, struct {
				Name string
				Uses string
				If   string
				Run  string
				ID   string
				With map[string]string
			}{s.Name, s.Uses, s.If, s.Run, s.ID, s.With})
		}
	}
	return out
}

// TestWorkflowPinsEveryAction: this repository pins its base images by digest
// and its firecracker binaries by sha256, and the Dockerfile fails rather than
// shipping bytes nobody chose. An action referenced by a mutable tag -- @v4,
// @main -- is the one place that principle could leak, and it is the place with
// the most reach: an action runs with the job's token and its `packages: write`.
func TestWorkflowPinsEveryAction(t *testing.T) {
	w, _ := loadWorkflow(t)
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)

	found := false
	for _, s := range steps(w) {
		if s.Uses == "" {
			continue
		}
		found = true
		_, ref, ok := strings.Cut(s.Uses, "@")
		if !ok {
			t.Errorf("step %q uses %q with no ref at all", s.Name, s.Uses)
			continue
		}
		if !sha.MatchString(ref) {
			t.Errorf("step %q uses %q; pin it to a 40-character commit sha, not a movable tag", s.Name, s.Uses)
		}
	}
	if !found {
		t.Error("the workflow uses no actions at all; this check is asserting nothing")
	}
}

// TestWorkflowPushesOnlyOutsideAPullRequest: the job holds `packages: write`, so
// a push step that ran on pull_request would publish whatever a contributor's
// branch built under the name a stranger installs from.
func TestWorkflowPushesOnlyOutsideAPullRequest(t *testing.T) {
	w, _ := loadWorkflow(t)

	// Counted separately: `docker login` guarded while `docker push` is not is a
	// hole, and a workflow that logs in but never pushes builds nothing anyone
	// can install. One counter cannot tell those apart.
	verbs := map[string]int{"docker push": 0, "docker login": 0}
	for _, s := range steps(w) {
		for verb := range verbs {
			if !strings.Contains(s.Run, verb) {
				continue
			}
			verbs[verb]++
			if !strings.Contains(s.If, "pull_request") {
				t.Errorf("step %q runs %q but is not conditioned on the event not being a pull_request (if: %q)",
					s.Name, verb, s.If)
			}
		}
	}
	for verb, n := range verbs {
		if n == 0 {
			t.Errorf("no step runs %q; the workflow builds an image nobody can install", verb)
		}
	}
}

// TestWorkflowBuildsTheShippedDockerfile: `scripts/vmobs-container build` passes
// --file deploy/Dockerfile and --build-arg SOURCE_REVISION, and the second one
// is why `docker exec vmobs cat /opt/vmobs/SOURCE_REVISION` can answer at all.
// A workflow that omitted it would publish images that all say "unknown".
func TestWorkflowBuildsTheShippedDockerfile(t *testing.T) {
	w, _ := loadWorkflow(t)

	var build string
	for _, s := range steps(w) {
		if strings.Contains(s.Run, "docker build") {
			build = s.Run
		}
	}
	if build == "" {
		t.Fatal("no step runs docker build")
	}
	for _, want := range []string{"deploy/Dockerfile", "SOURCE_REVISION"} {
		if !strings.Contains(build, want) {
			t.Errorf("the docker build step does not mention %q:\n%s", want, build)
		}
	}
}

// TestWorkflowFetchesTheGuestImagesRatherThanBuildingThem: the guest kernel is
// not reproducible. Measured on the host that built the artifacts the lock
// currently pins, its banner reads
//
//	Linux version 6.1.186 (root@86c79b11d7c2) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1)
//	... #2 SMP PREEMPT_DYNAMIC Tue Sep  1 14:43:49 UTC 2026
//
// and four things in it vary between builds: the build container's random
// hostname, the toolchain version from an unpinned apt-get, the .version counter
// and the timestamp. A workflow that ran images/build-all.sh would produce a
// different vmlinux, and lock-pins.sh would exit 1 comparing it to the pin --
// correctly, but after a kernel compile, and reading like a broken build rather
// than like the design error it is.
func TestWorkflowFetchesTheGuestImagesRatherThanBuildingThem(t *testing.T) {
	w, _ := loadWorkflow(t)

	fetches := false
	for _, s := range steps(w) {
		if strings.Contains(s.Run, "build-all.sh") {
			t.Errorf("step %q runs images/build-all.sh; the kernel is not reproducible, so a rebuild cannot match the digest runtime.lock.json pins", s.Name)
		}
		if strings.Contains(s.Run, "fetch-guest-images") {
			fetches = true
			if s.If != "" {
				t.Errorf("step %q fetches the guest images but is conditional (if: %q); deploy/Dockerfile needs them on every build", s.Name, s.If)
			}
		}
	}
	if !fetches {
		t.Error("no step runs scripts/fetch-guest-images; deploy/Dockerfile copies images/dist/vmlinux and images/dist/rootfs.ext4, and neither is in the checkout")
	}
}
