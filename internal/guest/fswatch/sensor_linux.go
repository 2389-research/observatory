// ABOUTME: Collects real filesystem-wide fanotify mutations into the bounded guest telemetry ring.
// ABOUTME: Publishes mount exclusions, late path uncertainty, kernel loss and collector failures.
//go:build linux

package fswatch

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/guest/telemetry"
	"golang.org/x/sys/unix"
)

const mutationMask = unix.FAN_CREATE | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_RENAME | unix.FAN_DELETE | unix.FAN_ATTRIB | unix.FAN_ONDIR

// Sensor owns one bounded kernel queue and at most one descriptor per monitored filesystem.
// The guest reporter is memory-only, so collection does not write into its observed disks.
type Sensor struct {
	fd        int
	reporter  *telemetry.Reporter
	roots     map[string]int
	mounts    map[string][]Mount
	health    telemetry.Sensor
	inventory string
	buffer    []byte
	mark      func(int, uint, uint64, int, string) error
	closeFD   func(int) error
}

func Open(r *telemetry.Reporter) (*Sensor, error) {
	s := &Sensor{fd: -1, reporter: r, roots: map[string]int{}, mounts: map[string][]Mount{}, buffer: make([]byte, 64*1024), health: telemetry.Sensor{ID: "filesystem", State: telemetry.SensorStarting, Dropped: "0", CaptureMode: "fanotify_filesystem", Limitations: []string{"mmap/msync/munmap changes are outside notification guarantees", "close_write does not prove content changed", "late paths are inferred; process lifetime identity unknown", "new mounts discovered every 2 seconds; mutations before marking are unobserved", "mount inventory bounded to 256 records; filesystem descriptors bounded to 64", "mount display labels truncate at 80 bytes; mutation names retain raw bytes", "shared telemetry ring drops are aggregate transport loss and cannot be attributed to one sensor"}}}
	s.mark = unix.FanotifyMark
	s.closeFD = unix.Close
	previous := restoreHealth(r)
	if previous.State != "" {
		s.health.State = previous.State
		s.health.Reason = previous.Reason
	}
	s.health.UnknownLossIntervals = previous.UnknownLossIntervals
	s.health.Dropped = previous.Dropped
	s.health.LastEventAt = previous.LastEventAt
	for _, c := range classes {
		s.health.EventClasses = append(s.health.EventClasses, c.kind)
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME_TARGET, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		err = normalizeInitError(err)
		s.fail(err)
		return nil, err
	}
	s.fd = fd
	return s, nil
}
func (s *Sensor) Close() error {
	for key, fd := range s.roots {
		_ = unix.Close(fd)
		delete(s.roots, key)
	}
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}
func (s *Sensor) fail(err error) {
	recordFailure(s.reporter, &s.health, err)
}
func (s *Sensor) emit(kind string, v any) {
	err := push(s.reporter, &s.health, kind, v)
	if err != nil && !errors.Is(err, errPayloadLimit) {
		s.fail(err)
	}
}

// Refresh observes mount topology, testing the exact production mark on each ext4 filesystem.
func (s *Sensor) Refresh() error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	_ = f.Close()
	if err != nil {
		return err
	}
	if len(b) > 1024*1024 {
		return fmt.Errorf("mountinfo exceeds 1 MiB")
	}
	mounts, err := parseMounts(string(b))
	if err != nil {
		return err
	}
	next := map[string][]Mount{}
	unsupportedReason := ""
	failureReason := ""
	s.health.Exclusions = nil
	s.health.Scope = nil
	markHealthy(&s.health)
	for _, m := range mounts {
		if m.Type != "ext4" {
			s.health.Exclusions = append(s.health.Exclusions, fmt.Sprintf("mount %d %s: %s outside supported persisted ext4 scope", m.ID, coverageLabel(m.Point), m.Type))
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(m.Point, &st); err != nil {
			reason := fmt.Sprintf("mount %d: statfs: %v", m.ID, err)
			s.health.Exclusions = append(s.health.Exclusions, reason)
			s.health.State = telemetry.SensorDegraded
			if s.health.Reason == "" {
				s.health.Reason = reason
			}
			if failureReason == "" {
				failureReason = reason
			}
			continue
		}
		fsid := fmt.Sprintf("%x", fsidBytes(st.Fsid.Val))
		next[fsid] = append(next[fsid], m)
	}
	for key, list := range next {
		if _, exists := s.roots[key]; !exists {
			if len(s.roots) >= 64 {
				reason := "filesystem descriptor limit exceeded"
				s.health.Exclusions = append(s.health.Exclusions, reason)
				s.health.State = telemetry.SensorDegraded
				if failureReason == "" {
					failureReason = reason
				}
				delete(next, key)
				continue
			}
			fd, err := unix.Open(list[0].Point, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err == nil {
				err = normalizeInitError(s.mark(s.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, mutationMask, unix.AT_FDCWD, list[0].Point))
			}
			if err != nil {
				if fd >= 0 {
					_ = unix.Close(fd)
				}
				reason := fmt.Sprintf("mount %d: fanotify capability: %v", list[0].ID, err)
				s.health.Exclusions = append(s.health.Exclusions, reason)
				s.health.State = telemetry.SensorDegraded
				if s.health.Reason == "" {
					s.health.Reason = reason
				}
				if unsupportedError(err) && unsupportedReason == "" {
					unsupportedReason = reason
				} else if !unsupportedError(err) && failureReason == "" {
					failureReason = reason
				}
				delete(next, key)
				continue
			}
			s.roots[key] = fd
		}
		for _, m := range list {
			s.health.Scope = append(s.health.Scope, fmt.Sprintf("mount %d %s ext4 fsid=%s", m.ID, coverageLabel(m.Point), key))
		}
	}
	s.mounts = next
	if len(next) == 0 {
		finishNoMarks(&s.health, unsupportedReason, failureReason)
	}
	s.removeMissingMarks(next)
	if len(next) > 0 {
		s.health.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	s.reporter.Sensors().Set(s.health)
	fingerprint := coverageFingerprint(s.health)
	if fingerprint != s.inventory {
		s.inventory = fingerprint
		s.emit("fs.coverage", s.health)
	}
	return nil
}

func finishNoMarks(h *telemetry.Sensor, unsupportedReason, failureReason string) {
	switch {
	case unsupportedReason != "" && failureReason == "":
		h.State = telemetry.SensorUnsupported
		h.Reason = unsupportedReason
	case failureReason != "":
		h.State = telemetry.SensorUnavailable
		h.Reason = failureReason
	default:
		h.State = telemetry.SensorUnavailable
		h.Reason = "no supported filesystem marks"
	}
}

func (s *Sensor) removeMissingMarks(next map[string][]Mount) {
	for key, fd := range s.roots {
		if _, ok := next[key]; ok {
			continue
		}
		if err := s.mark(s.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_FILESYSTEM, mutationMask, fd, "."); err != nil {
			s.health.State = telemetry.SensorDegraded
			s.health.Reason = "failed to remove stale filesystem mark"
			s.health.Exclusions = append(s.health.Exclusions, fmt.Sprintf("fsid %s: remove stale fanotify mark: %v", key, err))
			continue
		}
		_ = s.closeFD(fd)
		delete(s.roots, key)
	}
}
func fsidBytes(vals [2]int32) []byte {
	b := make([]byte, 8)
	binary.NativeEndian.PutUint32(b, uint32(vals[0]))
	binary.NativeEndian.PutUint32(b[4:], uint32(vals[1]))
	return b
}
func (s *Sensor) resolve(e *Event) {
	for _, id := range e.Identities {
		e.Mounts = append(e.Mounts, s.mounts[id.FSID]...)
		if e.PathStatus != "unresolved" || id.Role == "old_parent" {
			continue
		}
		root, ok := s.roots[id.FSID]
		if !ok {
			continue
		}
		handle, err := base64.StdEncoding.DecodeString(id.HandleBase64)
		if err != nil {
			continue
		}
		fd, err := unix.OpenByHandleAt(root, unix.NewFileHandle(id.HandleType, handle), unix.O_PATH|unix.O_CLOEXEC)
		if err != nil {
			continue
		}
		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		_ = unix.Close(fd)
		if err != nil || strings.HasSuffix(path, " (deleted)") {
			continue
		}
		if id.NameBase64 != "" {
			name, err := base64.StdEncoding.DecodeString(id.NameBase64)
			if err != nil {
				continue
			}
			path = filepath.Join(path, string(name))
		}
		e.PathStatus = "inferred"
		e.PathBase64 = base64.StdEncoding.EncodeToString([]byte(path))
		e.PathDisplay = strconv.QuoteToASCII(path)
		if utf8.ValidString(path) {
			e.Path = path
		}
	}
}
func (s *Sensor) read() error {
	n, err := unix.Read(s.fd, s.buffer)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return nil
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return io.EOF
	}
	events, err := decode(s.buffer[:n])
	if err != nil {
		return err
	}
	for _, e := range events {
		if e.Mask&unix.FAN_Q_OVERFLOW != 0 {
			s.health.UnknownLossIntervals++
			s.health.State = telemetry.SensorDegraded
			s.health.Reason = "fanotify queue overflow: lost count unknown"
			s.emit("fs.loss", map[string]any{"sensor": "filesystem", "reason": "fanotify_queue_overflow", "lost_count": nil, "count_quality": "unknown"})
			continue
		}
		s.resolve(&e)
		for _, kind := range e.kinds() {
			e.Operation = strings.TrimPrefix(kind, "fs.")
			s.emit(kind, e)
		}
		s.health.LastEventAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	s.reporter.Sensors().Set(s.health)
	return nil
}

// Run retries unavailable collectors with bounded delay and records each failure.
func Run(ctx context.Context, r *telemetry.Reporter) {
	for ctx.Err() == nil {
		s, err := Open(r)
		if err == nil {
			err = s.Refresh()
			refresh := time.Now().Add(2 * time.Second)
			for err == nil && ctx.Err() == nil {
				err = s.read()
				if err == nil && time.Now().After(refresh) {
					err = s.Refresh()
					refresh = time.Now().Add(2 * time.Second)
				}
				select {
				case <-ctx.Done():
				case <-time.After(20 * time.Millisecond):
				}
			}
			if err != nil {
				s.fail(err)
			}
			_ = s.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
