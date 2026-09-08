// ABOUTME: Service-level import diagnostics use actual spool files, SQLite and HTTP.
// ABOUTME: The importer endpoints need no VM runtime and do not boot a fake guest.
package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

func TestHTTPVMImportHealthHidesForeignOwner(t *testing.T) {
	srv, st, _ := newAuthServer(t)
	_, client := loginAndGetSession(t, srv.URL)
	foreign, _ := seedForeignVM(t, t.Context(), st)
	var bodies [][]byte
	for _, id := range []string{foreign, "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"} {
		resp, err := client.Get(srv.URL + "/api/v1/vms/" + id + "/telemetry/import")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		bodies = append(bodies, body)
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("foreign and absent diagnostics differ: %s / %s", bodies[0], bodies[1])
	}
}

func TestHTTPImportRootFailureRecovery(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	root := filepath.Join(t.TempDir(), "spool")
	if err := os.WriteFile(root, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	eng := situation.New(st, situation.Config{})
	eng.SetImporter(imp)
	srv := httptest.NewServer(api.New(st, eng, nil, api.AuthConfig{}, nil, nil))
	defer srv.Close()
	read := func() spool.ImportStatus {
		t.Helper()
		resp, err := http.Get(srv.URL + "/api/v1/telemetry/import")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var status spool.ImportStatus
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if got := read(); got.State != "unknown" {
		t.Fatalf("before cycle = %+v", got)
	}
	if _, err := imp.ImportOnce(t.Context()); err == nil {
		t.Fatal("root failure missing")
	}
	if got := read(); got.State != "degraded" || got.ConsecutiveFailures != "1" || got.LastError == "" {
		t.Fatalf("failure = %+v", got)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.State != "healthy" || got.LastSuccessAt == "" {
		t.Fatalf("recovery = %+v", got)
	}
}

func TestHTTPVMImportFailureHealthAndUnknownVM(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	boot := "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	_, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID: id, Name: "import-health", Owner: "local_operator", TemplateID: "tmpl", TemplateDigest: "sha256:abc", VCPUCount: 1, MemoryMiB: 128, RootDiskMiB: 64, WorkspaceDiskMiB: 64, MemoryTotalMiB: 256, NetworkProfile: "transport", NetworkPolicyID: "public-web", Labels: map[string]string{}, Kind: "vm.create", RequestHash: strings.Repeat("a", 64), Admit: func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"starting", "running"} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: id, To: state, Reason: "service test", OperationID: op.OperationID, BootID: &boot}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Append(t.Context(), &events.Envelope{
		SchemaVersion: 1, VMID: &id, BootID: &boot, SourceInstanceID: "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa", SourceSeq: "0", Kind: "guest.sensor_health", Provenance: events.GuestReported, Sensor: "guestd", HostReceivedAt: events.Timestamp{Time: time.Now().UTC()}, Quality: events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable}, Data: map[string]any{},
	}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	seg := filepath.Join(dir, "seg-0000000000000000.vmsp")
	if err := os.WriteFile(seg, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	eng := situation.New(st, situation.Config{})
	eng.SetImporter(imp)
	srv := httptest.NewServer(api.New(st, eng, nil, api.AuthConfig{}, nil, nil))
	defer srv.Close()
	get := func(path string) map[string]any {
		t.Helper()
		resp, err := http.Get(srv.URL + "/api/v1" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
		var value map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if get("/vms/" + id)["telemetry_health"] != "healthy" {
		t.Fatal("fresh heartbeat must be healthy")
	}
	if _, err := imp.ImportOnce(t.Context()); err == nil {
		t.Fatal("missing failure")
	}
	if get("/vms/" + id)["telemetry_health"] != "degraded" {
		t.Fatal("fresh heartbeat hid failed importer")
	}
	if get("/vms/" + id + "/telemetry/import")["consecutive_failures"] != "1" {
		t.Fatal("missing current failure count")
	}
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if get("/vms/" + id)["telemetry_health"] != "healthy" {
		t.Fatal("recovery did not clear health fault")
	}
	resp, err := http.Get(srv.URL + "/api/v1/vms/ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb/telemetry/import")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unknown VM = %d", resp.StatusCode)
	}
}
