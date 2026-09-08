// ABOUTME: Decodes bounded fanotify FID records while retaining original names and handles.
// ABOUTME: Notifications carry uncertain process and path attribution, never content claims.
package fswatch

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
)

type Identity struct {
	Role         string `json:"role"`
	FSID         string `json:"fsid"`
	HandleType   int32  `json:"handle_type"`
	HandleBase64 string `json:"handle_base64"`
	NameBase64   string `json:"name_base64,omitempty"`
	NameDisplay  string `json:"name_display,omitempty"`
}
type Event struct {
	Mask            uint64     `json:"mask"`
	PID             int32      `json:"pid"`
	ProcessIdentity string     `json:"process_identity"`
	PathStatus      string     `json:"path_status"`
	Path            string     `json:"path,omitempty"`
	PathBase64      string     `json:"path_base64,omitempty"`
	PathDisplay     string     `json:"path_display,omitempty"`
	IsDirectory     bool       `json:"is_directory"`
	Identities      []Identity `json:"identities"`
	Mounts          []Mount    `json:"mounts,omitempty"`
	MountStatus     string     `json:"mount_status"`
	Operation       string     `json:"operation"`
}

var classes = []struct {
	mask uint64
	kind string
}{
	{0x100, "fs.create"}, {0x2, "fs.modify"}, {0x8, "fs.close_write"},
	{0x10000000, "fs.rename"}, {0x200, "fs.delete"}, {0x4, "fs.metadata"},
}

func (e Event) kinds() []string {
	var out []string
	for _, c := range classes {
		if e.Mask&c.mask != 0 {
			out = append(out, c.kind)
		}
	}
	return out
}
func decode(b []byte) ([]Event, error) {
	var out []Event
	for len(b) > 0 {
		if len(b) < 24 {
			return nil, fmt.Errorf("short fanotify metadata")
		}
		n := int(binary.NativeEndian.Uint32(b))
		h := int(binary.NativeEndian.Uint16(b[6:]))
		if n < 24 || n > len(b) || h < 24 || h > n || b[4] != 3 {
			return nil, fmt.Errorf("invalid fanotify metadata")
		}
		if int32(binary.NativeEndian.Uint32(b[16:])) != -1 {
			return nil, fmt.Errorf("unexpected descriptor in FID group")
		}
		e := Event{Mask: binary.NativeEndian.Uint64(b[8:]), PID: int32(binary.NativeEndian.Uint32(b[20:])), PathStatus: "unresolved", ProcessIdentity: "unknown", MountStatus: "candidate_context"}
		e.IsDirectory = e.Mask&0x40000000 != 0
		for info := b[h:n]; len(info) > 0; {
			if len(info) < 4 {
				return nil, fmt.Errorf("short fanotify info")
			}
			size := int(binary.NativeEndian.Uint16(info[2:]))
			if size < 4 || size > len(info) {
				return nil, fmt.Errorf("invalid fanotify info length")
			}
			typ := info[0]
			rec := info[:size]
			info = info[size:]
			roles := map[byte]string{1: "file", 2: "parent", 3: "parent", 10: "old_parent", 12: "new_parent"}
			role, known := roles[typ]
			if !known {
				continue
			}
			if size < 20 {
				return nil, fmt.Errorf("short file handle")
			}
			count := uint64(binary.NativeEndian.Uint32(rec[12:]))
			if count > uint64(size-20) {
				return nil, fmt.Errorf("invalid file handle length")
			}
			end := 20 + int(count)
			id := Identity{Role: role, FSID: fmt.Sprintf("%x", rec[4:12]), HandleType: int32(binary.NativeEndian.Uint32(rec[16:])), HandleBase64: base64.StdEncoding.EncodeToString(rec[20:end])}
			if typ == 2 || typ == 10 || typ == 12 {
				name := rec[end:]
				i := bytes.IndexByte(name, 0)
				if i < 0 {
					return nil, fmt.Errorf("unterminated file name")
				}
				name = name[:i]
				id.NameBase64 = base64.StdEncoding.EncodeToString(name)
				id.NameDisplay = strconv.QuoteToASCII(string(name))
			}
			e.Identities = append(e.Identities, id)
		}
		out = append(out, e)
		b = b[n:]
	}
	return out, nil
}
