// ABOUTME: Verifies daemon HTTP connection bounds with real sockets.
// ABOUTME: Short test deadlines exercise the same server configuration as serve.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHTTPServerBounds(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []string{"body", "headers", "idle", "large", "normal"} {
			t.Run(fmt.Sprintf("tls=%v/%s", secure, mode), func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "body read failed", http.StatusRequestTimeout)
						return
					}
					_, _ = w.Write([]byte("ok"))
				})
				srv := boundedHTTPServer(handler)
				if srv.ReadTimeout != 30*time.Second || srv.ReadHeaderTimeout != 5*time.Second || srv.IdleTimeout != 60*time.Second || srv.MaxHeaderBytes != 32<<10 || srv.WriteTimeout != 0 {
					t.Fatalf("incorrect server limits: %+v", srv)
				}
				srv.ReadTimeout = 80 * time.Millisecond
				srv.ReadHeaderTimeout = 50 * time.Millisecond
				srv.IdleTimeout = 50 * time.Millisecond
				ts := httptest.NewUnstartedServer(handler)
				ts.Config = srv
				if secure {
					ts.StartTLS()
				} else {
					ts.Start()
				}
				defer ts.Close()
				var conn net.Conn
				var err error
				if secure {
					conn, err = tls.Dial("tcp", ts.Listener.Addr().String(), ts.Client().Transport.(*http.Transport).TLSClientConfig)
				} else {
					conn, err = net.Dial("tcp", ts.Listener.Addr().String())
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				switch mode {
				case "body":
					fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 50\r\n\r\n{")
				case "headers":
					fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost:")
				case "large":
					fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: local\r\nX-Large: %s\r\n\r\n", strings.Repeat("x", 40<<10))
				default:
					fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: local\r\n\r\n")
				}
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, nil)
				if mode == "headers" {
					if err == nil {
						response.Body.Close()
						t.Fatal("stalled headers accepted")
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						t.Fatal("header timeout not enforced")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.ReadAll(response.Body)
				response.Body.Close()
				want := 200
				if mode == "body" {
					want = 408
				}
				if mode == "large" {
					want = 431
				}
				if response.StatusCode != want {
					t.Fatalf("status=%d want=%d", response.StatusCode, want)
				}
				if mode == "idle" {
					_, err = reader.ReadByte()
					if err == nil {
						t.Fatal("idle connection stayed open")
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						t.Fatal("idle timeout not enforced")
					}
				}
			})
		}
	}
}

func TestHTTPBoundsPreserveUpgradedWebSocket(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		for {
			kind, body, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err = c.Write(r.Context(), kind, body); err != nil {
				return
			}
		}
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.Config = boundedHTTPServer(handler)
	ts.Config.ReadTimeout = 30 * time.Millisecond
	ts.Config.IdleTimeout = 30 * time.Millisecond
	ts.Start()
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, strings.Replace(ts.URL, "http:", "ws:", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	time.Sleep(120 * time.Millisecond)
	if err = c.Write(ctx, websocket.MessageText, []byte("still here")); err != nil {
		t.Fatal(err)
	}
	_, body, err := c.Read(ctx)
	if err != nil || string(body) != "still here" {
		t.Fatalf("upgraded stream: %q %v", body, err)
	}
}
