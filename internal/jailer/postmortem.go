// ABOUTME: Rescues a failed launch's runner artifacts before rollback deletes the state directory.
// ABOUTME: The stage name says which step failed; only these bytes say why it failed.
package jailer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/2389-research/observatory/internal/durable"
)

const (
	// failedDirName holds one archive per failed launch, at <StateDir>/failed.
	// It sits beside vms/ rather than inside it because allocateSlot and
	// Reconcile both walk <StateDir>/vms and read every entry as a VM.
	failedDirName = "failed"

	// maxRescueBytes bounds one rescued artifact. A runner that failed to attach
	// writes a few kilobytes; the cap is here so a runner stuck in a log loop
	// cannot fill the host through the failure path (P-01).
	maxRescueBytes = 256 << 10

	// maxRescuedLaunches bounds how many archives are kept. Older ones are the
	// least likely to still be under investigation, and an unbounded pile of
	// them is the same disk problem one size larger.
	maxRescuedLaunches = 16

	// truncationMarkerPrefix opens the first line of a rescued artifact that had
	// to be cut. A truncated log that looks whole is a lie about what the runner
	// printed, so the file says what it dropped.
	truncationMarkerPrefix = "[rescued tail:"
)

// rescuedArtifacts names the files worth keeping out of a VM's state directory.
//
// The capability token is that directory's other file and is deliberately not
// here: §15.3 keeps it out of every record that outlives the boot, and these
// archives outlive it by design. The manifest is not here either — it describes
// resources that no longer exist by the time the rescue runs.
var rescuedArtifacts = []string{"runner.log", "runner-state.json"}

// rescueFailedLaunch copies the runner's log and phase file out of
// <StateDir>/vms/<vmID> into a new archive under <StateDir>/failed, and returns
// the archive's path. It exists because doRollback removes that state directory,
// and for a launch that failed at runner_spawned or attached the log inside it
// is the only record of the fatal step — the stage name alone is a symptom with
// no cause.
//
// Returns "" when there was nothing to rescue, which is the normal case for a
// launch that failed before the runner ever wrote anything. No archive is
// created then: a directory of empty archives buries the ones that hold
// something.
//
// The source files are read, not moved. doRollback removes the whole state
// directory immediately after, and a rescue that emptied it first would be a
// trap for any later caller that does not.
//
// The M1a gate harness rescues the same two files for VMs it can still see
// (tests/integration/postmortem_test.go). It cannot see these ones: a failed
// launch has already deleted the directory by the time the test reads the
// error. The two mechanisms cover opposite halves of the same problem.
func rescueFailedLaunch(stateDir, vmID, bootID string) (string, error) {
	srcDir := filepath.Join(stateDir, "vms", vmID)

	type artifact struct {
		name string
		body []byte
	}
	var (
		keep     []artifact
		problems []error
	)
	for _, name := range rescuedArtifacts {
		body, err := readTail(filepath.Join(srcDir, name), maxRescueBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if len(body) == 0 {
			continue
		}
		keep = append(keep, artifact{name: name, body: body})
	}
	if len(keep) == 0 {
		return "", errors.Join(problems...)
	}

	failedDir := filepath.Join(stateDir, failedDirName)
	archive := filepath.Join(failedDir, archiveName(time.Now().UTC(), vmID, bootID))
	if err := durable.MkdirAll(archive, 0o700); err != nil {
		problems = append(problems, fmt.Errorf("jailer: rescue %s: %w", vmID, err))
		return "", errors.Join(problems...)
	}
	landed := 0
	for _, a := range keep {
		if err := durable.WriteFile(filepath.Join(archive, a.name), 0o600, a.body); err != nil {
			problems = append(problems, fmt.Errorf("jailer: rescue %s: %w", vmID, err))
			continue
		}
		landed++
	}
	if landed == 0 {
		// Every write failed — the disk-full case, since the directory above them
		// was created a moment earlier. Returning the path would point the launch
		// error at an empty directory, which reads as "the log is here" and is
		// worse than saying nothing.
		_ = os.RemoveAll(archive)
		return "", errors.Join(problems...)
	}

	// Prune after writing, so the archive this call was made for is the newest
	// name present and cannot be the one discarded.
	problems = append(problems, pruneRescued(failedDir, maxRescuedLaunches))
	return archive, errors.Join(problems...)
}

// archiveName is the directory one rescue lands in: the time it was taken, then
// the VM and the boot attempt it belongs to. Leading with a fixed-width UTC
// timestamp makes the names sort chronologically, which is how pruning picks
// what to drop.
//
// Both ids are server-minted opaque identifiers (§5.3), never caller-supplied,
// but the name is built by concatenation and a separator reaching it would put
// the rollback's writes outside the state directory. archiveSegment settles that
// here rather than relying on where the ids come from today.
func archiveName(at time.Time, vmID, bootID string) string {
	return at.Format("20060102T150405Z") + "-" + archiveSegment(vmID) + "-" + archiveSegment(bootID)
}

// archiveSegment reduces an identifier to one safe path component: letters,
// digits, dot, dash and underscore survive, everything else becomes "_".
func archiveSegment(s string) string {
	const maxSegment = 64
	if len(s) > maxSegment {
		s = s[:maxSegment]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// readTail returns the last max bytes of path. A file within the cap comes back
// byte for byte; a larger one comes back as a marker line naming what was
// dropped, followed by exactly the last max bytes. The tail is the useful half:
// the step that killed the launch is the last thing the runner printed.
func readTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("jailer: rescue %s: %w", path, err)
	}
	size := info.Size()
	if size <= max {
		body, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("jailer: rescue %s: %w", path, err)
		}
		return body, nil
	}

	if _, err := f.Seek(size-max, io.SeekStart); err != nil {
		return nil, fmt.Errorf("jailer: rescue %s: %w", path, err)
	}
	tail := make([]byte, max)
	if _, err := io.ReadFull(f, tail); err != nil {
		return nil, fmt.Errorf("jailer: rescue %s: %w", path, err)
	}
	marker := fmt.Sprintf("%s last %d of %d bytes; earlier output dropped]\n", truncationMarkerPrefix, max, size)
	return append([]byte(marker), tail...), nil
}

// pruneRescued keeps the newest keep archives in dir and removes the rest.
// ReadDir returns names in order and archiveName leads with a timestamp, so the
// tail of that list is the newest.
//
// The removals are not made durable: a crash that loses one leaves an archive
// over the cap until the next failed launch prunes again, which is a cheaper
// answer than fsyncing a directory on the way out of a failure path.
func pruneRescued(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("jailer: prune rescued launches: %w", err)
	}
	if len(entries) <= keep {
		return nil
	}
	var problems []error
	for _, e := range entries[:len(entries)-keep] {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			problems = append(problems, fmt.Errorf("jailer: prune rescued launch %s: %w", e.Name(), err))
		}
	}
	return errors.Join(problems...)
}
