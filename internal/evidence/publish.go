// ABOUTME: Publishes each execution once under a name that cannot be reused, and reads records back.
// ABOUTME: Exclusive create is the immutability; recomputed digests are the tamper check.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/2389-research/observatory-v2/internal/durable"
)

// maxArtifactBytes bounds one published artifact. Gate transcripts run to a
// few kilobytes; the cap is here so a runaway log cannot be filed as evidence
// and fill the host that was supposed to be observed.
const maxArtifactBytes = 8 << 20

// Publish writes one record and refuses to replace an existing one. That
// refusal is the immutability: a rerun that wants to say something different
// has to be a new execution with a new id, which leaves the earlier answer
// standing beside it.
//
// Invalid records never reach the disk — Validate runs first, so a directory
// never holds a claim the rules would have rejected.
func Publish(dir string, e Execution) error {
	if err := Validate(e); err != nil {
		return fmt.Errorf("evidence: refusing to publish %s: %w", e.ExecutionID, err)
	}
	body, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: encode %s: %w", e.ExecutionID, err)
	}
	return publishExclusive(dir, e.ExecutionID+".json", append(body, '\n'))
}

// PublishArtifact writes bytes beside the records and returns the binding a
// record carries for them. The digest is taken from the bytes handed in, and
// Verify later recomputes it from the file, so the two disagree exactly when
// something changed the file afterwards.
func PublishArtifact(dir, name string, body []byte) (Artifact, error) {
	if !safeName(name) {
		return Artifact{}, fmt.Errorf("evidence: artifact name %q must be one lowercase name", name)
	}
	if len(body) == 0 {
		return Artifact{}, fmt.Errorf("evidence: artifact %q is empty: it would verify forever and prove nothing", name)
	}
	if len(body) > maxArtifactBytes {
		return Artifact{}, fmt.Errorf("evidence: artifact %q is %d bytes, over the %d-byte cap", name, len(body), maxArtifactBytes)
	}
	if err := publishExclusive(dir, name, body); err != nil {
		return Artifact{}, err
	}
	digest := sha256.Sum256(body)
	return Artifact{Path: name, SHA256: hex.EncodeToString(digest[:])}, nil
}

// publishExclusive lands body at dir/name, or fails because that name is
// taken. It writes a temporary file first and links it into place: a crash
// before the link leaves a temporary nobody reads, where writing straight to
// the final name would leave a truncated record under a name Publish then
// refuses to reuse — a claim permanently stuck half-written.
//
// link(2) does not follow the destination, so a symlink planted at the record
// name fails the same way an existing record does, rather than redirecting the
// write somewhere the reader will never look.
func publishExclusive(dir, name string, body []byte) error {
	if err := durable.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	final := filepath.Join(dir, name)

	temp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("evidence: create temporary for %s: %w", name, err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := writeAndSync(temp, body); err != nil {
		return fmt.Errorf("evidence: write %s: %w", name, err)
	}
	if err := os.Link(tempName, final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("evidence: %s already exists and records are never rewritten", name)
		}
		return fmt.Errorf("evidence: publish %s: %w", name, err)
	}
	if err := os.Remove(tempName); err != nil {
		return fmt.Errorf("evidence: remove temporary for %s: %w", name, err)
	}
	return durable.SyncDir(dir)
}

// writeAndSync writes body to f, makes it durable and closes it. A record that
// is only in the page cache is not a record a crash leaves behind.
func writeAndSync(f *os.File, body []byte) error {
	if err := f.Chmod(0o600); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := f.Write(body); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// Load reads every record in dir, oldest first, and returns the ones it can
// trust together with an error naming each one it cannot. Both halves matter:
// a tampered record must not disappear quietly, and one bad file must not hide
// the rest of the history.
//
// A directory that is not there yet holds no records and is not an error.
func Load(dir string) ([]Execution, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", dir, err)
	}

	var (
		out      []Execution
		problems []error
	)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		e, err := loadRecord(dir, name)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		out = append(out, e)
	}
	sortExecutions(out)
	return out, errors.Join(problems...)
}

// loadRecord reads one record and refuses it unless its filename is its own
// execution id. Addressing a record by two names would let a copy sit beside
// the original claiming the same execution, which is what Publish's exclusive
// name exists to prevent.
func loadRecord(dir, name string) (Execution, error) {
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return Execution{}, fmt.Errorf("evidence: %s: %w", name, err)
	}
	var e Execution
	if err := json.Unmarshal(body, &e); err != nil {
		return Execution{}, fmt.Errorf("evidence: %s: %w", name, err)
	}
	if want := e.ExecutionID + ".json"; name != want {
		return Execution{}, fmt.Errorf("evidence: %s holds execution %s, which belongs in %s", name, e.ExecutionID, want)
	}
	if err := Validate(e); err != nil {
		return Execution{}, fmt.Errorf("evidence: %s: %w", name, err)
	}
	return e, nil
}

// Verify recomputes every artifact digest from the bytes now in dir. A record
// whose artifacts are missing or altered is not downgraded to a weaker claim —
// it stops being evidence, and the error says which file and what was expected
// so the reader can go and look.
func Verify(dir string, e Execution) error {
	var problems []error
	for _, a := range e.Manifest.Artifacts {
		got, err := digestFile(filepath.Join(dir, a.Path))
		if err != nil {
			problems = append(problems, fmt.Errorf("evidence: %s artifact %q: %w", e.ExecutionID, a.Path, err))
			continue
		}
		if got != a.SHA256 {
			problems = append(problems, fmt.Errorf("evidence: %s artifact %q: bytes hash to %s, record says %s", e.ExecutionID, a.Path, got, a.SHA256))
		}
	}
	return errors.Join(problems...)
}

func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Names lists the record files in dir, for a caller that wants to report where
// evidence landed without reading it.
func Names(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", dir, err)
	}
	var out []string
	for _, entry := range entries {
		if name := entry.Name(); !entry.IsDir() && !strings.HasPrefix(name, ".") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}
