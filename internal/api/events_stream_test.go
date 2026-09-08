// ABOUTME: Exercises durable SSE replay and live delivery over real HTTP and SQLite.
// ABOUTME: Checks cursor/filter isolation, bounded requests and long-lived auth loss.
package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/store"
)

func appendStreamEvent(t *testing.T, st *store.Store, vm, boot, source, seq string) string {
	t.Helper()
	e := &events.Envelope{SchemaVersion: 1, VMID: &vm, BootID: &boot, SourceInstanceID: source, SourceSeq: seq, Kind: "fs.modify", Provenance: events.GuestReported, Sensor: "filesystem", HostReceivedAt: events.Timestamp{Time: time.Now().UTC()}, Quality: events.Quality{PathResolution: events.PathExactAtCapture, Attribution: events.AttributionNotApplicable}, Data: map[string]any{"path_display": "/workspace/<script>\nsecret-looking-data"}}
	r, err := st.Append(t.Context(), e)
	if err != nil {
		t.Fatal(err)
	}
	return r.EventID
}
func openEventStream(t *testing.T, client *http.Client, url string, headers map[string]string) (*http.Response, *bufio.Reader, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("stream status=%d body=%s", resp.StatusCode, b)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("stream headers: %v", resp.Header)
	}
	return resp, bufio.NewReader(resp.Body), cancel
}
func readEventFrame(t *testing.T, r *bufio.Reader) (id, kind string, data []byte) {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			if len(data) > 0 {
				return
			}
			continue
		}
		if strings.HasPrefix(line, "id: ") {
			id = strings.TrimPrefix(line, "id: ")
		}
		if strings.HasPrefix(line, "event: ") {
			kind = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			data = append(data, strings.TrimPrefix(line, "data: ")...)
		}
	}
}
func TestEventsStreamReplayLiveAndResume(t *testing.T) {
	srv, st := newServer(t)
	vm, boot := testUUID(100), testUUID(101)
	source := testUUID(102)
	first := appendStreamEvent(t, st, vm, boot, source, "1")
	second := appendStreamEvent(t, st, vm, boot, source, "2")
	appendStreamEvent(t, st, testUUID(200), boot, testUUID(201), "1")
	appendStreamEvent(t, st, vm, testUUID(300), testUUID(301), "1")
	endpoint := srv.URL + "/api/v1/events/stream?vm_id=" + vm + "&boot_id=" + boot + "&family=fs&after=0&limit=1"
	resp, reader, cancel := openEventStream(t, http.DefaultClient, endpoint, map[string]string{"Last-Event-ID": first})
	id, kind, data := readEventFrame(t, reader)
	if id != second || kind != "" {
		t.Fatalf("resume id=%s event=%s", id, kind)
	}
	var env events.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.VMID == nil || *env.VMID != vm || env.BootID == nil || *env.BootID != boot || env.Data["path_display"] != "/workspace/<script>\nsecret-looking-data" {
		t.Fatalf("stream changed event: %+v", env)
	}
	live := appendStreamEvent(t, st, vm, boot, source, "3")
	id, _, _ = readEventFrame(t, reader)
	if id != live {
		t.Fatalf("live id=%s want=%s", id, live)
	}
	cancel()
	resp.Body.Close()
	next := appendStreamEvent(t, st, vm, boot, source, "4")
	_, reader, _ = openEventStream(t, http.DefaultClient, endpoint, map[string]string{"Last-Event-ID": live})
	id, _, _ = readEventFrame(t, reader)
	if id != next {
		t.Fatalf("reconnect id=%s want=%s", id, next)
	}
}
func TestEventsBootFilterAndInvalidRequests(t *testing.T) {
	srv, st := newServer(t)
	vm := testUUID(100)
	boot := testUUID(101)
	appendStreamEvent(t, st, vm, boot, testUUID(102), "1")
	appendStreamEvent(t, st, vm, testUUID(103), testUUID(104), "1")
	var page struct {
		Events []events.Envelope `json:"events"`
	}
	getJSON(t, srv.URL+"/api/v1/events?vm_id="+vm+"&boot_id="+boot, 200, &page)
	if len(page.Events) != 1 || *page.Events[0].BootID != boot {
		t.Fatalf("boot filter: %+v", page)
	}
	for _, path := range []string{"/events?boot_id=BAD", "/events/stream?boot_id=BAD", "/events/stream?after=nope", "/events/stream?until=3", "/events/stream?limit=33", "/events/stream?kind=fs.modify&family=fs"} {
		var e api.Error
		getJSON(t, srv.URL+"/api/v1"+path, 400, &e)
		if strings.Contains(path, "limit=33") && e.Details["max"] != float64(32) {
			t.Fatalf("stream limit reports wrong bound: %+v", e)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events/stream?after=0", nil)
	req.Header.Set("Last-Event-ID", "invalid")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("invalid header cursor status=%d", resp.StatusCode)
	}
}
func TestEventsStreamTailOnlyAppliesToInitialPage(t *testing.T) {
	srv, st := newServer(t)
	vm, boot, source := testUUID(1), testUUID(2), testUUID(3)
	var ids []string
	for i := 1; i <= 5; i++ {
		ids = append(ids, appendStreamEvent(t, st, vm, boot, source, strconv.Itoa(i)))
	}
	_, reader, _ := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream?tail=true&limit=2", nil)
	for _, want := range ids[3:] {
		id, _, _ := readEventFrame(t, reader)
		if id != want {
			t.Fatalf("tail id=%s want=%s", id, want)
		}
	}
	for i := 6; i <= 9; i++ {
		ids = append(ids, appendStreamEvent(t, st, vm, boot, source, strconv.Itoa(i)))
	}
	for _, want := range ids[5:] {
		id, _, _ := readEventFrame(t, reader)
		if id != want {
			t.Fatalf("forward id=%s want=%s", id, want)
		}
	}
}
func TestEventsStreamTokenRevocationAndExpiry(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(fmt.Sprintf("expire=%t", expire), func(t *testing.T) {
			srv, st, creds := newAuthServer(t)
			ttl := time.Duration(0)
			if expire {
				ttl = 400 * time.Millisecond
			}
			secret, record, err := creds.CreateToken("stream", testOperator, ttl)
			if err != nil {
				t.Fatal(err)
			}
			_, reader, _ := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream", map[string]string{"Authorization": "Bearer " + secret})
			if !expire {
				if err := creds.RevokeToken(record.ID); err != nil {
					t.Fatal(err)
				}
				appendStreamEvent(t, st, testUUID(1), testUUID(2), testUUID(3), "1")
			}
			id, kind, data := readEventFrame(t, reader)
			if id != "" || kind != "stream_error" || strings.Contains(string(data), secret) {
				t.Fatalf("auth-loss frame id=%s kind=%s body=%s", id, kind, data)
			}
			var e api.Error
			if err := json.Unmarshal(data, &e); err != nil {
				t.Fatal(err)
			}
			if e.Code != "unauthenticated" {
				t.Fatalf("auth-loss error: %+v", e)
			}
			rest, err := io.ReadAll(reader)
			if err != nil || len(rest) != 0 {
				t.Fatalf("continued after auth loss: %q %v", rest, err)
			}
		})
	}
}
func TestEventsStreamStoreFailureClosesSafely(t *testing.T) {
	srv, st := newServer(t)
	_, reader, _ := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream", nil)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	id, kind, data := readEventFrame(t, reader)
	if id != "" || kind != "stream_error" || strings.Contains(string(data), "sqlite") || strings.Contains(string(data), "closed") {
		t.Fatalf("unsafe storage error: %s %s %s", id, kind, data)
	}
	var e api.Error
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e.Cause != "storage_failure" {
		t.Fatalf("wrong storage error: %+v", e)
	}
	if rest, err := io.ReadAll(reader); err != nil || len(rest) != 0 {
		t.Fatalf("stream failed to close: %q %v", rest, err)
	}
}

func TestEventsStreamSessionLogoutAndInitialAuthentication(t *testing.T) {
	srv, _, _ := newAuthServer(t)
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/events/stream", 401, &e)
	csrf, client := loginAndGetSession(t, srv.URL)
	_, reader, _ := openEventStream(t, client, srv.URL+"/api/v1/events/stream?kind=fs.modify", nil)
	response := doWithCSRF(t, client, http.MethodPost, srv.URL+"/api/v1/auth/logout", csrf, nil, "")
	response.Body.Close()
	if response.StatusCode != 204 && response.StatusCode != 200 {
		t.Fatalf("logout status=%d", response.StatusCode)
	}
	id, kind, data := readEventFrame(t, reader)
	if id != "" || kind != "stream_error" || !strings.Contains(string(data), "unauthenticated") {
		t.Fatalf("logout did not end stream: %s %s %s", id, kind, data)
	}
}
func TestEventsStreamCapacityReleasedByCancellation(t *testing.T) {
	srv, _ := newServer(t)
	var cancels []context.CancelFunc
	for i := 0; i < 32; i++ {
		_, _, cancel := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream", nil)
		cancels = append(cancels, cancel)
	}
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/events/stream", 503, &e)
	if e.Cause != "event_stream_limit" || e.Details["max"] != float64(32) {
		t.Fatalf("wrong stream bound: %+v", e)
	}
	for _, cancel := range cancels {
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(srv.URL + "/api/v1/events/stream")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled stream retained capacity")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestEventsStreamOverridesServerWriteTimeoutPerFrame(t *testing.T) {
	original, st := newServer(t)
	srv := httptest.NewUnstartedServer(original.Config.Handler)
	srv.Config.WriteTimeout = 20 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	_, reader, _ := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream", nil)
	time.Sleep(40 * time.Millisecond) // Expire the server's initial response deadline.
	want := appendStreamEvent(t, st, testUUID(1), testUUID(2), testUUID(3), "1")
	id, _, _ := readEventFrame(t, reader)
	if id != want {
		t.Fatalf("stream lost event after idle: %s want %s", id, want)
	}
}
func TestEventsStreamSlowReaderReleasesHandler(t *testing.T) {
	original, st := newServer(t)
	vm, boot := testUUID(1), testUUID(2)
	for i := 1; i <= 64; i++ {
		env := &events.Envelope{SchemaVersion: 1, VMID: &vm, BootID: &boot, SourceInstanceID: testUUID(3), SourceSeq: strconv.Itoa(i), Kind: "fs.modify", Provenance: events.GuestReported, Sensor: "filesystem", HostReceivedAt: events.Timestamp{Time: time.Now().UTC()}, Quality: events.Quality{PathResolution: events.PathUnresolved, Attribution: events.AttributionNotApplicable}, Data: map[string]any{"detail": strings.Repeat("x", 128<<10)}}
		if _, err := st.Append(t.Context(), env); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		original.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	address, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "GET /api/v1/events/stream HTTP/1.1\r\nHost: "+address.String()+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		t.Fatal("unread response retained handler past write deadline")
	}
}

func TestEventsStreamManifestNamesItsBounds(t *testing.T) {
	srv, _ := newServer(t)
	var meta metaResponse
	getJSON(t, srv.URL+"/api/v1/meta", 200, &meta)
	if !meta.Features["events_stream"] || meta.Links["events_stream"] != "/api/v1/events/stream" || meta.Limits["events_stream_page_max"] != 32 || meta.Limits["events_stream_connections_max"] != 32 || meta.Limits["events_stream_frame_max_bytes"] != 1<<20 {
		t.Fatalf("stream discovery lacks enforced bounds: %+v", meta)
	}
}
func TestEventsStreamRetainsSharedHostObservationScope(t *testing.T) {
	srv, st, creds := newAuthServer(t)
	want := appendStreamEvent(t, st, testUUID(1), testUUID(2), testUUID(3), "1")
	// SPEC §14 deliberately keeps events shared across authenticated operators.
	// Resource ownership is not an event privacy boundary.
	for _, owner := range []string{testOperator, "another_operator"} {
		token, _, err := creds.CreateToken("reader", owner, 0)
		if err != nil {
			t.Fatal(err)
		}
		resp, reader, cancel := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream?kind=fs.modify", map[string]string{"Authorization": "Bearer " + token})
		id, _, _ := readEventFrame(t, reader)
		cancel()
		resp.Body.Close()
		if id != want {
			t.Fatalf("shared scope for %s yielded %s, want %s", owner, id, want)
		}
	}
}

func TestEventsStreamFrameBoundIncludesSSEFraming(t *testing.T) {
	srv, st := newServer(t)
	vm, boot, id := testUUID(1), testUUID(2), "1"
	env := &events.Envelope{SchemaVersion: 1, EventID: &id, VMID: &vm, BootID: &boot, SourceInstanceID: testUUID(3), SourceSeq: "1", Kind: "fs.modify", Provenance: events.GuestReported, Sensor: "filesystem", HostReceivedAt: events.Timestamp{Time: time.Now().UTC()}, Quality: events.Quality{PathResolution: events.PathUnresolved, Attribution: events.AttributionNotApplicable}, Data: map[string]any{"detail": ""}}
	base, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Data["detail"] = strings.Repeat("x", (1<<20)-1-len(base))
	env.EventID = nil
	result, err := st.Append(t.Context(), env)
	if err != nil {
		t.Fatal(err)
	}
	if result.EventID != "1" {
		t.Fatalf("fixture cursor=%s", result.EventID)
	}
	_, reader, _ := openEventStream(t, http.DefaultClient, srv.URL+"/api/v1/events/stream", nil)
	cursor, kind, data := readEventFrame(t, reader)
	if cursor != "" || kind != "stream_error" || len(data) > 1024 {
		t.Fatalf("oversized frame emitted: cursor=%s kind=%s bytes=%d", cursor, kind, len(data))
	}
}
