// ABOUTME: Template registry: loads immutable approved-template manifests and
// ABOUTME: computes their digest at load time (never trusted from the file itself).
package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Template is an immutable approved-template record (SPEC §5.1). The Digest is
// computed from the manifest file bytes on load; it is never read from the
// manifest itself — a file claiming a false digest would be a configuration lie.
type Template struct {
	TemplateID             string            `json:"template_id"`
	Description            string            `json:"description"`
	KernelImage            string            `json:"kernel_image"`
	RootImage              string            `json:"root_image"`
	GuestPrivilegeProfiles []string          `json:"guest_privilege_profiles"`
	Sensors                []string          `json:"sensors"`
	ProtocolVersions       map[string]string `json:"protocol_versions"`
	// Digest is populated by LoadTemplates, not from the JSON.
	Digest string `json:"-"`
}

// ErrTemplateUnknown is returned when a requested template ID is not in the
// approved registry. The caller should include the known IDs in the remediation.
var ErrTemplateUnknown = errors.New("template not found in approved registry")

// LoadTemplates reads every *.json manifest in dir with strict unknown-field
// checking (malformed = hard error, not skip). A missing dir is an empty
// registry — a host with no approved templates is a truthful state.
// Digest is computed from file bytes, never taken from the manifest.
func LoadTemplates(dir string) (map[string]Template, error) {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return map[string]Template{}, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read templates dir %s: %w", dir, err)
	}

	out := make(map[string]Template, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read template %s: %w", path, err)
		}
		var t Template
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", path, err)
		}
		sum := sha256.Sum256(raw)
		t.Digest = "sha256:" + hex.EncodeToString(sum[:])
		out[t.TemplateID] = t
	}
	return out, nil
}
