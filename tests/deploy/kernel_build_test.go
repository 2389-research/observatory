// ABOUTME: Checks kernel builds return bind-mounted files to the invoking user.
// ABOUTME: The Docker fixture exercises real ownership and repeat-build cleanup.
package deploy_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const kernelBuildPath = "../../images/kernel/build.sh"

func TestKernelBuildPassesCallerOwnership(t *testing.T) {
	code := readFile(t, kernelBuildPath)
	for _, want := range []string{`-e HOST_UID="$(id -u)"`, `-e HOST_GID="$(id -g)"`} {
		if !strings.Contains(code, want) {
			t.Errorf("kernel container does not receive caller identity: %s", want)
		}
	}
}

func TestKernelBuildOwnershipDocker(t *testing.T) {
	if os.Getenv("VMOBS_KERNEL_BUILD_TEST") != "1" {
		t.Skip("set VMOBS_KERNEL_BUILD_TEST=1 to exercise ownership in Docker")
	}
	code := readFile(t, kernelBuildPath)
	_, container, ok := strings.Cut(code, "bash -euo pipefail -c '\n")
	if !ok {
		t.Fatal("kernel container command missing")
	}
	// Run the real container setup through its cleanup trap, replacing only the
	// expensive download/compile body with actual root-owned fixture files.
	setup, _, ok := strings.Cut(container, `echo "[docker] installing build deps..."`)
	if !ok {
		t.Fatal("kernel dependency installation boundary missing")
	}
	pins := readFile(t, "../../images/rootfs/pins.env")
	_, ref, ok := strings.Cut(pins, `BASE_IMAGE_REF="`)
	if !ok {
		t.Fatal("base image pin missing")
	}
	ref, _, _ = strings.Cut(ref, `"`)
	for _, tc := range []struct {
		name string
		end  string
		code int
	}{
		{"success", "exit 0", 0},
		{"failed_compile", "exit 23", 23},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := setup + `
mkdir -p /build/linux/include/config
touch /build/linux/include/config/GENERATED
touch /build/dist/vmlinux /build/dist/kernel.config /build/dist/kernel.config.sha256
` + tc.end
			fixture := `set -euo pipefail
mkdir -p /build/linux /build/dist
touch /build/dist/unrelated
chown 1234:1234 /build /build/linux /build/dist
set +e
bash -euo pipefail -c "$1"
status=$?
set -e
test "$status" -eq "$2"
for file in /build/linux /build/linux/include/config/GENERATED /build/dist/vmlinux /build/dist/kernel.config /build/dist/kernel.config.sha256; do
    actual=$(stat -c %u:%g "$file")
    if [ "$actual" != 1234:1234 ]; then
        echo "$file owner $actual; want 1234:1234" >&2
        exit 1
    fi
done
test "$(stat -c %u:%g /build/dist/unrelated)" = 0:0
setpriv --reuid 1234 --regid 1234 --clear-groups sh -ec '
    rm -rf /build/linux
    mkdir /build/linux
    echo next-build > /build/dist/vmlinux
'
`
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none",
				"-e", "HOST_UID=1234", "-e", "HOST_GID=1234", ref,
				"bash", "-c", fixture, "ownership-fixture", build, fmt.Sprint(tc.code))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("kernel ownership fixture: %v\n%s", err, out)
			}
		})
	}
}
