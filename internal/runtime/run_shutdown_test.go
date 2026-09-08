// ABOUTME: Run mutations share the manager admission gate during shutdown.
// ABOUTME: Rejected work cannot touch storage after lifecycle drain completes.
package runtime_test

import (
	"errors"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
)

func TestRunMutationsRefuseAfterShutdownBegins(t *testing.T) {
	st := openStoreForManager(t)
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), defaultCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	mgr.BeginClose()
	for name, mutate := range map[string]func() error{
		"create": func() error {
			_, _, err := mgr.CreateRun(t.Context(), runtime.RunRequest{VMID: "absent"})
			return err
		},
		"conclude": func() error {
			_, err := mgr.ConcludeRun(t.Context(), "absent", nil, true, "shutdown")
			return err
		},
		"progress": func() error {
			_, err := mgr.SubmitRunProgress(t.Context(), "absent", []byte(`{}`))
			return err
		},
		"result": func() error {
			_, err := mgr.SubmitRunResult(t.Context(), "absent", []byte(`{}`))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			var unavailable *runtime.UnavailableError
			if err := mutate(); !errors.As(err, &unavailable) {
				t.Fatalf("mutation passed the closing gate: %v", err)
			}
		})
	}
}
