// ABOUTME: Exercises real fanotify mutation events on a supplied isolated Linux filesystem.
// ABOUTME: Requires an explicit privileged fixture; never substitutes mocked kernel events.
//go:build linux

package fswatch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest/telemetry"
	"golang.org/x/sys/unix"
)

func TestRealFilesystemMutations(t *testing.T) {
	root := os.Getenv("VMOBS_FANOTIFY_TEST_ROOT")
	if root == "" {
		t.Skip("requires isolated ext4 fixture: VMOBS_FANOTIFY_TEST_ROOT via scripts/vmobs-gate")
	}
	reporter := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 1024})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sensor, err := Open(reporter)
	if err != nil {
		t.Fatal(err)
	}
	defer sensor.Close()
	if err := sensor.Refresh(); err != nil {
		t.Fatal(err)
	}
	pid := int32(os.Getpid())
	fixtureID := fmt.Sprintf("%d-%d", pid, time.Now().UnixNano())
	baseName := "fanotify-fixture-" + fixtureID
	dir := filepath.Join(root, baseName)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	rawFileName := []byte("file-" + fixtureID + "\xff\n")
	file := filepath.Join(dir, string(rawFileName))
	linkName := "link-" + fixtureID
	renameName := "renamed-" + fixtureID
	if err := os.WriteFile(file, []byte("real content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(file, 2); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(dir, linkName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file, filepath.Join(dir, renameName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, renameName)); err != nil {
		t.Fatal(err)
	}
	fixtureFSID, fixtureMountID := fixtureMount(t, sensor, root)
	wantedNames := map[string]bool{
		base64.StdEncoding.EncodeToString(rawFileName):        true,
		base64.StdEncoding.EncodeToString([]byte(linkName)):   true,
		base64.StdEncoding.EncodeToString([]byte(renameName)): true,
	}
	// Read synchronously: these fixture mutations belong to the collector PID.
	deadline := time.Now().Add(3 * time.Second)
	seen := map[string]bool{}
	var observed []string
	hostileNameSeen := false
	diagnosticLogged := false
	for time.Now().Before(deadline) {
		if err := sensor.read(); err != nil {
			t.Fatal(err)
		}
		for {
			item, ok := reporter.Ring().Next()
			if !ok {
				break
			}
			var event Event
			if err := json.Unmarshal(item.Data, &event); err != nil {
				t.Fatal(err)
			}
			if len(observed) < 8 {
				observed = append(observed, eventSummary(item.Kind, event))
			}
			if event.PID == pid && eventHasFixtureIdentity(event, fixtureFSID, fixtureMountID, wantedNames) {
				if eventHasName(event, base64.StdEncoding.EncodeToString(rawFileName)) {
					hostileNameSeen = true
				}
				switch event.PathStatus {
				case "unresolved":
					diagnostic := "already logged"
					if !diagnosticLogged {
						diagnostic = unresolvedHandleDiagnostic(sensor, event, fixtureFSID)
						diagnosticLogged = true
					}
					t.Fatalf("live fixture parent handle did not resolve through sensor root descriptor: %s; event=%+v", diagnostic, event)
				case "inferred":
					rawPath, err := base64.StdEncoding.DecodeString(event.PathBase64)
					if err != nil || !strings.HasPrefix(string(rawPath), dir+"/") {
						t.Fatalf("inferred path is inconsistent with fixture: path=%q err=%v event=%+v", rawPath, err, event)
					}
				default:
					t.Fatalf("unexpected path status %q: %+v", event.PathStatus, event)
				}
				seen[item.Kind] = true
			}
			reporter.Ring().AckThrough(item.Seq)
		}
		if len(seen) == 6 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var missing []string
	for _, kind := range []string{"fs.create", "fs.modify", "fs.close_write", "fs.rename", "fs.delete", "fs.metadata"} {
		if !seen[kind] {
			missing = append(missing, kind)
		}
	}
	if len(missing) > 0 || !hostileNameSeen {
		t.Fatalf("fixture evidence missing kinds=%v hostile_name=%t for pid %d fsid=%s mount=%d; bounded events: %v", missing, hostileNameSeen, pid, fixtureFSID, fixtureMountID, observed)
	}
}

func fixtureMount(t *testing.T, sensor *Sensor, root string) (string, int) {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		t.Fatal(err)
	}
	fsid := fmt.Sprintf("%x", fsidBytes(st.Fsid.Val))
	bestID, bestLen := 0, -1
	for _, mount := range sensor.mounts[fsid] {
		if (root == mount.Point || strings.HasPrefix(root, strings.TrimSuffix(mount.Point, "/")+"/")) && len(mount.Point) > bestLen {
			bestID, bestLen = mount.ID, len(mount.Point)
		}
	}
	if bestLen < 0 {
		t.Fatalf("fixture root %q absent from sensor scope %+v", root, sensor.mounts[fsid])
	}
	return fsid, bestID
}

func eventHasFixtureIdentity(event Event, fsid string, mountID int, wantedNames map[string]bool) bool {
	hasName, hasFSID, hasMount := false, false, false
	for _, identity := range event.Identities {
		hasName = hasName || wantedNames[identity.NameBase64]
		hasFSID = hasFSID || identity.FSID == fsid
	}
	for _, mount := range event.Mounts {
		hasMount = hasMount || mount.ID == mountID
	}
	return hasName && hasFSID && hasMount
}

func eventHasName(event Event, encoded string) bool {
	for _, identity := range event.Identities {
		if identity.NameBase64 == encoded {
			return true
		}
	}
	return false
}

func eventSummary(kind string, event Event) string {
	names := make([]string, 0, len(event.Identities))
	for _, identity := range event.Identities {
		if identity.NameBase64 != "" {
			names = append(names, identity.NameBase64)
		}
	}
	mounts := make([]int, 0, len(event.Mounts))
	for _, mount := range event.Mounts {
		mounts = append(mounts, mount.ID)
	}
	return fmt.Sprintf("kind=%s pid=%d path=%s names=%v mounts=%v", kind, event.PID, event.PathStatus, names, mounts)
}

func unresolvedHandleDiagnostic(sensor *Sensor, event Event, fsid string) string {
	rootFD, ok := sensor.roots[fsid]
	if !ok {
		return "fixture filesystem root descriptor absent"
	}
	for _, identity := range event.Identities {
		if identity.FSID != fsid || (identity.Role != "parent" && identity.Role != "old_parent" && identity.Role != "new_parent") {
			continue
		}
		handle, err := base64.StdEncoding.DecodeString(identity.HandleBase64)
		if err != nil {
			return fmt.Sprintf("decode parent handle: %v", err)
		}
		fd, err := unix.OpenByHandleAt(rootFD, unix.NewFileHandle(identity.HandleType, handle), unix.O_PATH|unix.O_CLOEXEC)
		if err != nil {
			return fmt.Sprintf("open_by_handle_at parent role=%s type=%d: %v", identity.Role, identity.HandleType, err)
		}
		_ = unix.Close(fd)
		return fmt.Sprintf("open_by_handle_at parent role=%s type=%d: success", identity.Role, identity.HandleType)
	}
	return "no parent handle in unresolved fixture event"
}

func TestCollectorFailureRetainsLossOnReopen(t *testing.T) {
	if os.Getenv("VMOBS_FANOTIFY_TEST_ROOT") == "" {
		t.Skip("requires privileged fanotify fixture")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{})
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	s.fail(os.ErrClosed)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.health.UnknownLossIntervals != 1 || s.health.Dropped != "0" {
		t.Fatalf("forgot collector failure: %+v", s.health)
	}
}

func TestRemoveMarkFailureStaysTrackedAndDegradesCoverage(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{})
	s := &Sensor{
		fd: 9, reporter: r, roots: map[string]int{"dead": 12}, mounts: map[string][]Mount{},
		health:  telemetry.Sensor{ID: "filesystem", State: telemetry.SensorHealthy, Dropped: "0"},
		mark:    func(int, uint, uint64, int, string) error { return unix.EIO },
		closeFD: func(int) error { t.Fatal("closed root after failed mark removal"); return nil },
	}
	s.removeMissingMarks(map[string][]Mount{})
	if _, ok := s.roots["dead"]; !ok || s.health.State != telemetry.SensorDegraded || len(s.health.Exclusions) == 0 {
		t.Fatalf("failed removal was hidden: roots=%v health=%+v", s.roots, s.health)
	}
}

func TestNoMarksPreservesStatfsFailureReason(t *testing.T) {
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorDegraded, Reason: "mount 7: statfs: stale file handle"}
	finishNoMarks(&h, "", h.Reason)
	if h.State != telemetry.SensorUnavailable || !strings.Contains(h.Reason, "statfs") {
		t.Fatalf("statfs failure hidden: %+v", h)
	}
}

func TestNoMarksReportsUnsupportedCapability(t *testing.T) {
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorDegraded}
	finishNoMarks(&h, "fanotify not supported", "")
	if h.State != telemetry.SensorUnsupported || h.Reason != "fanotify not supported" {
		t.Fatalf("unsupported marks = %+v", h)
	}
}

func TestRealQueueOverflow(t *testing.T) {
	root := os.Getenv("VMOBS_FANOTIFY_TEST_ROOT")
	if root == "" {
		t.Skip("requires isolated ext4 fixture via scripts/vmobs-gate")
	}
	raw, err := os.ReadFile("/proc/sys/fs/fanotify/max_queued_events")
	if err != nil {
		t.Fatal(err)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if limit > 65536 {
		t.Skipf("kernel queue %d exceeds bounded pressure fixture limit 65536", limit)
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 8})
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "fanotify-overflow-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// O_RDONLY creates exactly one mutation class, on distinct identities, without coalescing writes.
	for i := 0; i < limit+1; i++ {
		f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(i)), os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < limit+2 && s.health.UnknownLossIntervals == 0; i++ {
		if err := s.read(); err != nil {
			t.Fatal(err)
		}
	}
	if s.health.UnknownLossIntervals == 0 || s.health.Dropped != "0" || s.health.State != telemetry.SensorDegraded {
		t.Fatalf("kernel pressure not reported: %+v", s.health)
	}
	if r.Ring().Stats().Queued > 8 || r.Ring().Stats().Dropped == "0" {
		t.Fatalf("ring pressure not bounded/countable: %+v", r.Ring().Stats())
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s.health.State != telemetry.SensorHealthy || s.health.UnknownLossIntervals == 0 {
		t.Fatalf("refresh did not separate recovery from retained loss: %+v", s.health)
	}
}

func TestRealMmapIsOutsideModificationGuarantee(t *testing.T) {
	root := os.Getenv("VMOBS_FANOTIFY_TEST_ROOT")
	if root == "" {
		t.Skip("requires isolated ext4 fixture via scripts/vmobs-gate")
	}
	f, err := os.CreateTemp(root, "fanotify-mmap-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Truncate(4096); err != nil {
		t.Fatal(err)
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 1024})
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	mem, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	mem[0] = 'x'
	if err := unix.Msync(mem, unix.MS_SYNC); err != nil {
		t.Fatal(err)
	}
	if err := unix.Munmap(mem); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, 0); err != nil || b[0] != 'x' {
		t.Fatalf("mmap content: %v %v", b, err)
	}
	if err := s.read(); err != nil {
		t.Fatal(err)
	}
	for {
		item, ok := r.Ring().Next()
		if !ok {
			break
		}
		if item.Kind == "fs.modify" {
			var event Event
			if err := json.Unmarshal(item.Data, &event); err != nil {
				t.Fatal(err)
			}
			if event.PID == int32(os.Getpid()) {
				t.Fatalf("unexpected mmap modify notification: %s", item.Data)
			}
		}
		r.Ring().AckThrough(item.Seq)
	}
}
