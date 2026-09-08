// ABOUTME: Exercises the entrypoint shutdown sequence with real child processes.
// ABOUTME: The privileged helper must survive until the daemon finishes its drain.
package deploy_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEntrypointPreservesPrivdUntilDaemonDrains(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(raw), "shutdown() {")
	if start < 0 {
		t.Fatal("entrypoint shutdown function missing")
	}
	end := strings.Index(string(raw[start:]), "\n}\n")
	if end < 0 {
		t.Fatal("entrypoint shutdown function end missing")
	}
	shutdown := string(raw[start : start+end+3])
	dir := t.TempDir()
	// Each child installs a real signal trap and announces readiness. Daemon
	// drain checks the privileged process after its own signal was delivered.
	daemon := `trap 'sleep 0.1; if kill -0 "$PRIVD_PID" 2>/dev/null; then echo alive > "$TASK_DIR/result"; else echo gone > "$TASK_DIR/result"; fi; exit 0' TERM
touch "$TASK_DIR/daemon-ready"
while :; do sleep 0.05; done
`
	helper := `trap 'exit 0' TERM
touch "$TASK_DIR/helper-ready"
while :; do sleep 0.05; done
`
	for name, body := range map[string]string{"daemon": daemon, "helper": helper} {
		if err := os.WriteFile(filepath.Join(dir, name+".sh"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	script := `log() { :; }
bash "$TASK_DIR/helper.sh" &
privd_pid=$!
export PRIVD_PID=$privd_pid
bash "$TASK_DIR/daemon.sh" &
vmobsd_pid=$!
trap 'kill "$vmobsd_pid" "$privd_pid" 2>/dev/null || true' EXIT
while [ ! -f "$TASK_DIR/helper-ready" ] || [ ! -f "$TASK_DIR/daemon-ready" ]; do sleep 0.01; done
` + shutdown + "\nshutdown\n"
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Env = append(os.Environ(), "TASK_DIR="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shutdown: %v: %s", err, output)
	}
	result, err := os.ReadFile(filepath.Join(dir, "result"))
	if err != nil || string(result) != "alive\n" {
		t.Fatalf("daemon lost privd during drain: %q %v", result, err)
	}
}
