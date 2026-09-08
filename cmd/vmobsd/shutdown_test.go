// ABOUTME: Shutdown tracks real HTTP handlers until their final SQLite access.
// ABOUTME: A bounded drain timeout never claims the storage users have stopped.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/store"
)

func TestShutdownTracksHTTPStorageUsers(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "shutdown.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mgr, err := runtime.NewManager(st, runtime.ForHost(), runtime.ManagerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := trackedHTTPHandler(t.Context(), mgr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		if _, err := st.Diagnostics(r.Context()); err != nil {
			t.Errorf("late store read: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	response := make(chan error, 1)
	go func() {
		r, err := srv.Client().Get(srv.URL)
		if err == nil {
			r.Body.Close()
		}
		response <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := mgr.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("active handler drain=%v", err)
	}
	r, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var refusal api.Error
	if err := json.NewDecoder(r.Body).Decode(&refusal); err != nil {
		t.Error(err)
	}
	r.Body.Close()
	if refusal.RetryStrategy != "after_precondition" {
		t.Errorf("shutdown recovery strategy: %+v", refusal)
	}
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("late admission=%d", r.StatusCode)
	}
	close(release)
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	if err := mgr.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
}
