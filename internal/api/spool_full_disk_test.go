// ABOUTME: Proves kata 19g4's recovery story end to end on a filesystem that genuinely
// ABOUTME: runs out of space: the writer refuses, records the loss, and the importer catches up.
package api_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

// TestSpoolWriterRecoversFromARealFullDisk proves the writer refuses and
// recovers, the importer imports both segments, and an operator can read the
// cause from the API while it persists — all on a filesystem that really
// returns ENOSPC, per kata 19g4's done criterion.
func TestSpoolWriterRecoversFromARealFullDisk(t *testing.T) {
	mnt := smallFilesystem(t)

	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, boot := testUUID(1), testUUID(2)
	seedRunningVM(t, st, id, boot)

	spoolRoot := filepath.Join(mnt, "spool")
	dir := filepath.Join(spoolRoot, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	writerInstance := testUUID(3)
	lossInstance, healthInstance, channelInstance := testUUID(4), testUUID(5), testUUID(6)
	var lossSeq, healthSeq, channelSeq atomic.Uint64

	lossRecord := func(o spool.Outage) *events.Envelope {
		return &events.Envelope{
			SchemaVersion: 1, VMID: &id, BootID: &boot,
			SourceInstanceID: lossInstance, SourceSeq: strconv.FormatUint(lossSeq.Add(1), 10),
			Kind: "telemetry.loss", Provenance: events.HostObserved, Sensor: spool.Sensor,
			HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
			Quality:        events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable},
			Data:           o.Data(),
		}
	}
	healthRecord := func() *events.Envelope {
		return &events.Envelope{
			SchemaVersion: 1, VMID: &id, BootID: &boot,
			SourceInstanceID: healthInstance, SourceSeq: strconv.FormatUint(healthSeq.Add(1), 10),
			Kind: "guest.sensor_health", Provenance: events.GuestReported, Sensor: "guestd",
			HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
			Quality:        events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable},
			Data:           map[string]any{},
		}
	}
	channelRecord := func() *events.Envelope {
		return &events.Envelope{
			SchemaVersion: 1, VMID: &id, BootID: &boot,
			SourceInstanceID: channelInstance, SourceSeq: strconv.FormatUint(channelSeq.Add(1), 10),
			Kind: "guest.channel_established", Provenance: events.HostObserved, Sensor: spool.Sensor,
			HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
			Quality:        events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable},
			Data:           map[string]any{"protocol_version": 1, "capabilities_count": 0},
		}
	}
	// kinds alternates the two provenances on every call.
	kinds := []func() *events.Envelope{healthRecord, channelRecord}
	callNum := 0
	nextRecord := func() *events.Envelope {
		env := kinds[callNum%len(kinds)]()
		callNum++
		return env
	}

	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID: id, InstanceID: writerInstance, MaxSegmentBytes: 64 << 10, LossRecord: lossRecord,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Registered after smallFilesystem's own cleanups, so it runs first
	// (t.Cleanup is LIFO): the writer closes before the volume detaches.
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("close writer: %v", err)
		}
	})

	imp := spool.NewImporter(st, spoolRoot, time.Second, nil)
	eng := situation.New(st, situation.Config{Triggers: map[string]bool{"telemetry_degraded": true}, QueueMaxItems: 10, CollapseDuplicates: true})
	eng.SetImporter(imp)
	srv := httptest.NewServer(api.New(st, eng, nil, api.AuthConfig{}, nil, nil))
	defer srv.Close()

	var acked, refused []*events.Envelope
	var runnerRefused, guestRefused uint64
	appendAcked := func(env *events.Envelope) error {
		err := w.Append(env)
		if err == nil {
			acked = append(acked, env)
		}
		return err
	}
	countRefusal := func(env *events.Envelope) {
		refused = append(refused, env)
		if env.Provenance == events.GuestReported {
			guestRefused++
		} else {
			runnerRefused++
		}
	}

	// Step 1: append a few records of each kind while the disk has room, and
	// import them. They must be in the store.
	for i := 0; i < 4; i++ {
		if err := appendAcked(nextRecord()); err != nil {
			t.Fatalf("append %d with room on disk: %v", i, err)
		}
	}
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatalf("import with room on disk: %v", err)
	}
	requireInStore(t, st, id, acked)

	// Step 2: fill the volume with ballast outside the spool dir, in falling
	// sizes, until each size fails with ENOSPC.
	fillFilesystem(t, mnt)

	// Step 3: append until one fails with a real ENOSPC. Appends that
	// succeed on the way are acknowledged records.
	const maxAttempts = 500
	sawENOSPC := false
	for i := 0; i < maxAttempts && !sawENOSPC; i++ {
		env := nextRecord()
		err := appendAcked(env)
		if err == nil {
			continue
		}
		if !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("append refused for a non-ENOSPC reason: %v", err)
		}
		countRefusal(env)
		sawENOSPC = true
	}
	if !sawENOSPC {
		t.Fatalf("disk never returned ENOSPC after %d appends", maxAttempts)
	}

	// Step 4: several more appends of both provenances must all fail. No
	// segment may hold a refused record.
	const moreAttempts = 6
	for i := 0; i < moreAttempts; i++ {
		env := nextRecord()
		if err := appendAcked(env); err == nil {
			t.Fatalf("append %d of %s succeeded on a full disk", i, env.Kind)
		}
		countRefusal(env)
	}
	outageSegments := checkSegments(t, dir, refused)

	// Step 5: ImportOnce's own cursor write may itself fail on the full
	// filesystem, so its error is not asserted — only that the writer's
	// failure is now visible and counted correctly through the API.
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Logf("import while the disk is still full: %v (expected)", err)
	}

	var duringOutage map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+id+"/telemetry/import", http.StatusOK, &duringOutage)
	writer, ok := duringOutage["writer"].(map[string]any)
	if !ok {
		t.Fatalf("import status has no writer object: %v", duringOutage)
	}
	wantRunner, wantGuest := strconv.FormatUint(runnerRefused, 10), strconv.FormatUint(guestRefused, 10)
	if writer["state"] != "failing" {
		t.Errorf("writer.state = %v, want failing", writer["state"])
	}
	if cause, _ := writer["cause"].(string); !strings.Contains(cause, "no space left on device") {
		t.Errorf("writer.cause = %q, want it to contain %q", cause, "no space left on device")
	}
	if writer["runner_records_refused"] != wantRunner {
		t.Errorf("writer.runner_records_refused = %v, want %v", writer["runner_records_refused"], wantRunner)
	}
	if writer["guest_pushes_refused"] != wantGuest {
		t.Errorf("writer.guest_pushes_refused = %v, want %v", writer["guest_pushes_refused"], wantGuest)
	}

	ws := imp.Status(id).Writer
	if ws == nil || ws.State != "failing" {
		t.Fatalf("imp.Status(id).Writer = %+v, want state failing", ws)
	}
	if !strings.Contains(ws.Cause, "no space left on device") {
		t.Errorf("imp.Status writer cause = %q, want it to contain %q", ws.Cause, "no space left on device")
	}
	if ws.RunnerRecordsRefused != wantRunner || ws.GuestPushesRefused != wantGuest {
		t.Errorf("imp.Status writer counts = runner=%s guest=%s, want runner=%s guest=%s", ws.RunnerRecordsRefused, ws.GuestPushesRefused, wantRunner, wantGuest)
	}

	var attn attentionListResponse
	getJSON(t, srv.URL+"/api/v1/attention", http.StatusOK, &attn)
	if len(attn.Items) != 1 {
		t.Fatalf("open attention = %d items, want exactly 1: %+v", len(attn.Items), attn.Items)
	}
	if !strings.HasPrefix(attn.Items[0].Summary, "runner spool writer failing since") {
		t.Errorf("attention summary = %q, want prefix %q", attn.Items[0].Summary, "runner spool writer failing since")
	}

	// Step 6: free the space.
	removeBallast(t, mnt)

	// Step 7: one more append must now succeed, landing in a new, newest
	// segment holding exactly the loss record and this record. The failed
	// segment now ends with an end marker (retired by advance).
	recovered := nextRecord()
	if err := appendAcked(recovered); err != nil {
		t.Fatalf("append after freeing space: %v", err)
	}
	acked = append(acked, recovered)
	newest := checkSegments(t, dir, refused)
	if len(newest) == 0 {
		t.Fatal("no segment present after recovery")
	}
	sort.Strings(newest)
	newestSeg := newest[len(newest)-1]
	newestKinds, err := recordKinds(t, newestSeg)
	if err != nil {
		t.Fatalf("read newest segment %s: %v", filepath.Base(newestSeg), err)
	}
	if want := []string{"telemetry.loss", recovered.Kind}; len(newestKinds) != 2 || newestKinds[0] != want[0] || newestKinds[1] != want[1] {
		t.Errorf("newest segment holds %v, want exactly %v", newestKinds, want)
	}
	for _, segPath := range outageSegments {
		hasEnd, err := segmentEndsClean(segPath)
		if err != nil {
			t.Fatalf("check end marker on %s: %v", filepath.Base(segPath), err)
		}
		if !hasEnd {
			t.Errorf("failed segment %s has no end marker after recovery", filepath.Base(segPath))
		}
	}
	// Step 8: ImportOnce now succeeds and imports both segments.
	stats, err := imp.ImportOnce(t.Context())
	if err != nil {
		t.Fatalf("import after recovery: %v", err)
	}
	t.Logf("recovery import: appended=%d deduped=%d pruned=%d", stats.Appended, stats.Deduped, stats.Pruned)

	requireInStore(t, st, id, acked)
	requireNotInStore(t, st, id, refused)

	stored := storeEvents(t, st, id)
	idx := indexByKey(stored)
	loss := idx[recordKey(&events.Envelope{Kind: "telemetry.loss", SourceInstanceID: lossInstance, SourceSeq: strconv.FormatUint(lossSeq.Load(), 10)})]
	if loss == nil {
		t.Fatal("store is missing the telemetry.loss record")
	}
	wantData := map[string]string{
		"runner_records_refused": wantRunner,
		"guest_pushes_refused":   wantGuest,
		"guest_events_lost":      "unknown",
	}
	for field, want := range wantData {
		if got, _ := loss.Data[field].(string); got != want {
			t.Errorf("loss.data.%s = %v, want %q", field, loss.Data[field], want)
		}
	}
	lossCause, _ := loss.Data["cause"].(string)
	if !strings.Contains(lossCause, "no space left on device") {
		t.Errorf("loss.data.cause = %q, want it to contain %q", lossCause, "no space left on device")
	}
	start, _ := loss.Data["interval_start"].(string)
	end, _ := loss.Data["interval_end"].(string)
	startT, errStart := time.Parse(events.TimestampLayout, start)
	endT, errEnd := time.Parse(events.TimestampLayout, end)
	if errStart != nil || errEnd != nil {
		t.Fatalf("parse interval bounds start=%q (%v) end=%q (%v)", start, errStart, end, errEnd)
	}
	if startT.After(endT) {
		t.Errorf("interval_start %s is after interval_end %s", start, end)
	}

	for _, segPath := range outageSegments {
		if _, err := os.Stat(segPath); !os.IsNotExist(err) {
			t.Errorf("failed segment %s was not pruned (stat err=%v)", filepath.Base(segPath), err)
		}
	}

	// Step 9: the API now reports the writer healthy.
	var healthy map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+id+"/telemetry/import", http.StatusOK, &healthy)
	hw, ok := healthy["writer"].(map[string]any)
	if !ok {
		t.Fatalf("import status has no writer object: %v", healthy)
	}
	if hw["state"] != "healthy" {
		t.Errorf("writer.state = %v, want healthy", hw["state"])
	}
}

// requireInStore fails the test if any of envs is missing from the VM's
// stored events, matched by (kind, source_instance_id, source_seq).
func requireInStore(t *testing.T, st *store.Store, id string, envs []*events.Envelope) {
	t.Helper()
	idx := indexByKey(storeEvents(t, st, id))
	for _, env := range envs {
		if idx[recordKey(env)] == nil {
			t.Errorf("store is missing acknowledged %s", recordKey(env))
		}
	}
}

// requireNotInStore fails the test if any of envs made it into the VM's
// stored events: a refused Append must never reach the store.
func requireNotInStore(t *testing.T, st *store.Store, id string, envs []*events.Envelope) {
	t.Helper()
	idx := indexByKey(storeEvents(t, st, id))
	for _, env := range envs {
		if idx[recordKey(env)] != nil {
			t.Errorf("store holds refused %s", recordKey(env))
		}
	}
}

// storeEvents returns every event the store holds for id.
func storeEvents(t *testing.T, st *store.Store, id string) []*events.Envelope {
	t.Helper()
	res, err := st.Query(t.Context(), store.Query{VMID: &id, Limit: store.MaxPageLimit})
	if err != nil {
		t.Fatalf("query store: %v", err)
	}
	return res.Events
}

func indexByKey(envs []*events.Envelope) map[string]*events.Envelope {
	idx := make(map[string]*events.Envelope, len(envs))
	for _, env := range envs {
		idx[recordKey(env)] = env
	}
	return idx
}

// recordKey identifies an envelope by its dedup identity plus kind, so a
// refused attempt can never be confused with an acknowledged one of another kind.
func recordKey(env *events.Envelope) string {
	return env.Kind + "#" + env.SourceInstanceID + "#" + env.SourceSeq
}

// checkSegments reads every seg-*.vmsp file in dir with the real segment
// reader, logs what each holds, and fails the test if any of refused's
// records reached a durable frame: a refused Append must leave no trace.
// It returns the segment paths found.
func checkSegments(t *testing.T, dir string, refused []*events.Envelope) []string {
	t.Helper()
	refusedKeys := make(map[string]bool, len(refused))
	for _, env := range refused {
		refusedKeys[recordKey(env)] = true
	}
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no segment files present")
	}
	sawHeaderOnly := false
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		kinds, err := recordKinds(t, name)
		if err != nil {
			t.Fatalf("read segment %s: %v", filepath.Base(name), err)
		}
		iter, err := spool.ReadSegment(name)
		if err != nil {
			t.Fatalf("read segment %s: %v", filepath.Base(name), err)
		}
		for {
			env, err := iter.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", filepath.Base(name), err)
			}
			if refusedKeys[recordKey(env)] {
				t.Errorf("segment %s holds refused record %s", filepath.Base(name), recordKey(env))
			}
		}
		_ = iter.Close()
		if len(kinds) == 0 {
			sawHeaderOnly = true
		}
		t.Logf("segment %s: %d bytes, %d record(s): %v", filepath.Base(name), info.Size(), len(kinds), kinds)
	}
	t.Logf("header-only segment present: %v", sawHeaderOnly)
	return names
}

// recordKinds returns the Kind of every record in the segment at path, in order.
func recordKinds(t *testing.T, path string) ([]string, error) {
	t.Helper()
	iter, err := spool.ReadSegment(path)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var kinds []string
	for {
		env, err := iter.Next()
		if errors.Is(err, io.EOF) {
			return kinds, nil
		}
		if err != nil {
			return nil, err
		}
		kinds = append(kinds, env.Kind)
	}
}

// segmentEndsClean reports whether the segment at path ends with the 4-byte
// end marker.
func segmentEndsClean(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < 4 {
		return false, nil
	}
	tail := make([]byte, 4)
	if _, err := f.ReadAt(tail, info.Size()-4); err != nil {
		return false, err
	}
	return tail[0] == 0xFF && tail[1] == 0xFF && tail[2] == 0xFF && tail[3] == 0xFF, nil
}

// fillFilesystem writes ballast files directly under mnt (never inside the
// spool dir, never named *.vmsp) in falling sizes until each size fails with
// ENOSPC, leaving the volume with no usable free space.
func fillFilesystem(t *testing.T, mnt string) {
	t.Helper()
	n := 0
	for _, size := range []int{1 << 20, 64 << 10, 4 << 10} {
		buf := make([]byte, size)
		for {
			n++
			name := filepath.Join(mnt, fmt.Sprintf("ballast-%d.bin", n))
			if full := writeBallast(t, name, buf); full {
				break
			}
		}
	}
}

// writeBallast writes buf to a new file at name and reports whether the
// filesystem is full at this size: true when create, write or close failed
// with ENOSPC (the partial file, if any, is removed). Any other error fails
// the test.
func writeBallast(t *testing.T, name string, buf []byte) bool {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return true
		}
		t.Fatalf("create %s: %v", name, err)
	}
	n, werr := f.Write(buf)
	if werr == nil && n != len(buf) {
		werr = fmt.Errorf("short write: %d of %d bytes", n, len(buf))
	}
	serr := f.Sync()
	cerr := f.Close()
	if errors.Is(werr, syscall.ENOSPC) || errors.Is(serr, syscall.ENOSPC) || errors.Is(cerr, syscall.ENOSPC) {
		_ = os.Remove(name)
		return true
	}
	if werr != nil {
		t.Fatalf("write %s: %v", name, werr)
	}
	if serr != nil {
		t.Fatalf("sync %s: %v", name, serr)
	}
	if cerr != nil {
		t.Fatalf("close %s: %v", name, cerr)
	}
	return false
}

// removeBallast deletes every ballast file fillFilesystem created.
func removeBallast(t *testing.T, mnt string) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(mnt, "ballast-*.bin"))
	if err != nil {
		t.Fatalf("glob ballast: %v", err)
	}
	for _, name := range names {
		if err := os.Remove(name); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
}
