// ABOUTME: Exercises CLI request deadlines and bounded reads against real HTTP/TLS.
// ABOUTME: Checks transport failures remain useful and never print partial results.
package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIHTTPBounds(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []string{"headers", "body", "large", "truncated", "normal", "override"} {
			t.Run(fmt.Sprintf("tls=%v/%s", secure, mode), func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch mode {
					case "headers", "override":
						select {
						case <-time.After(150 * time.Millisecond):
						case <-r.Context().Done():
							return
						}
					case "body":
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
						<-r.Context().Done()
						return
					case "large":
						_, _ = w.Write(bytes.Repeat([]byte("x"), 16*1024*1024+1))
						return
					case "truncated":
						w.Header().Set("Content-Length", "100")
						_, _ = w.Write([]byte("{"))
						return
					}
					_, _ = w.Write([]byte(`{"ok":true}`))
				})
				s := httptest.NewUnstartedServer(handler)
				if secure {
					s.StartTLS()
				} else {
					s.Start()
				}
				defer s.Close()
				args := []string{"--api", s.URL, "--json", "--timeout", "60ms"}
				if mode == "normal" || mode == "large" || mode == "truncated" || mode == "override" {
					args[4] = "2s"
				}
				if secure {
					p := filepath.Join(t.TempDir(), "ca.pem")
					if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--ca", p)
				}
				args = append(args, "api", "GET", "/api/v1/meta")
				var out, errout bytes.Buffer
				started := time.Now()
				code := run(args, &out, &errout)
				if time.Since(started) > 3*time.Second {
					t.Fatal("request exceeded budget")
				}
				if mode == "normal" || mode == "override" {
					if code != exitOK || !strings.Contains(out.String(), `"ok":true`) {
						t.Fatalf("code=%d out=%s err=%s", code, &out, &errout)
					}
					return
				}
				want := "deadline exceeded"
				if mode == "large" {
					want = "response exceeds"
				}
				if mode == "truncated" {
					want = "read response"
				}
				matchesError := strings.Contains(errout.String(), want) || (mode == "headers" && strings.Contains(errout.String(), "timeout awaiting response headers"))
				if code != exitTransport || !matchesError || out.Len() != 0 {
					t.Fatalf("code=%d out length=%d err=%s", code, out.Len(), &errout)
				}
			})
		}
	}
}

func TestCLIRejectsNonpositiveTimeout(t *testing.T) {
	for _, v := range []string{"0", "-1s"} {
		var out, errout bytes.Buffer
		if code := run([]string{"--timeout", v, "meta"}, &out, &errout); code != exitUsage || !strings.Contains(errout.String(), "positive") {
			t.Fatalf("%s: %d %s", v, code, &errout)
		}
	}
}

func TestClientRequestContextBoundsBodyWithoutClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := client{base: srv.URL, httpClient: &http.Client{}, timeout: 40 * time.Millisecond}
	started := time.Now()
	_, body, err := c.do(http.MethodGet, "/", nil)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || len(body) != 0 {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("request context did not bound body")
	}
}
