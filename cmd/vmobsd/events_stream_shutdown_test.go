// ABOUTME: Verifies an open SSE reader cannot hold daemon shutdown or the store alive.
// ABOUTME: Runs the real serve path, tracked HTTP handler, listener and SQLite store.
package main

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestServeDrainsOpenEventStream(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, quietLogger(), func(addr string) { ready <- addr }) }()
	var address string
	select {
	case address = <-ready:
	case err := <-done:
		t.Fatalf("serve before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve not ready")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	// This request deliberately does not inherit the daemon context. Shutdown
	// must cancel it through the production trackedHTTPHandler boundary.
	response, err := client.Get("http://" + address + "/api/v1/events/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("not an open stream: status=%d headers=%v", response.StatusCode, response.Header)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown with live SSE: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("open SSE prevented tracked handler shutdown")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("shutdown failed to close stream cleanly: %v", err)
	}
}
