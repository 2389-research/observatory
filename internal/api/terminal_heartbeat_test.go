// ABOUTME: Exercises terminal heartbeat liveness through real WebSockets.
// ABOUTME: Quiet responsive browsers stay connected; peers ignoring pings expire.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestTerminalHeartbeat(t *testing.T) {
	for _, responsive := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing_pong", true: "quiet_browser"}[responsive], func(t *testing.T) {
			done := make(chan error, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = c.CloseNow() }()
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				go func() { _, _, _ = c.Read(ctx); cancel() }()
				done <- terminalHeartbeat(ctx, c, 20*time.Millisecond, 40*time.Millisecond)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http:", "ws:", 1), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.CloseNow() }()
			if responsive {
				go func() { _, _, _ = c.Read(ctx) }()
				select {
				case err := <-done:
					t.Fatalf("responsive idle browser closed: %v", err)
				case <-time.After(200 * time.Millisecond):
				}
				_ = c.CloseNow()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("heartbeat ended without cause")
				}
			case <-ctx.Done():
				t.Fatal("heartbeat did not end")
			}
		})
	}
}
