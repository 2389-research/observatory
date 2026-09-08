// ABOUTME: Parses Linux mountinfo into a bounded filesystem coverage inventory.
// ABOUTME: Mount IDs describe candidate context, not certain event attribution through bind mounts.
package fswatch

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Mount struct {
	ID          int    `json:"id"`
	Point       string `json:"point"`
	PointBase64 string `json:"point_base64,omitempty"`
	Type        string `json:"type"`
	Device      string `json:"device"`
}

func parseMounts(raw string) ([]Mount, error) {
	var out []Mount
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 10 || sep < 6 || sep+3 >= len(fields) {
			return nil, fmt.Errorf("invalid mountinfo record")
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		out = append(out, Mount{ID: id, Point: unescape.Replace(fields[4]), Type: fields[sep+1], Device: fields[2]})
		if !utf8.ValidString(out[len(out)-1].Point) {
			out[len(out)-1].PointBase64 = base64.StdEncoding.EncodeToString([]byte(out[len(out)-1].Point))
		}
		if len(out) > 256 {
			return nil, fmt.Errorf("mount inventory exceeds 256 records")
		}
	}
	return out, nil
}

// coverageLabel bounds display-only mount context so health fits the telemetry frame.
func coverageLabel(raw string) string {
	text := strconv.QuoteToASCII(raw)
	if len(text) > 80 {
		return text[:77] + "..."
	}
	return text
}
