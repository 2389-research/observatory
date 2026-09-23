// ABOUTME: White-box tests for parseSegmentName and segmentName, the
// ABOUTME: byte-exact segment filename codec nextSegmentIndex depends on.
package spool

import "testing"

func TestParseSegmentName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantIdx uint64
	}{
		{"zero", "seg-0000000000000000.vmsp", true, 0},
		{"mid", "seg-0000000000000042.vmsp", true, 42},
		{"max", "seg-9999999999999999.vmsp", true, 9999999999999999},
		{"15 digits", "seg-000000000000001.vmsp", false, 0},
		{"17 digits", "seg-00000000000000001.vmsp", false, 0},
		{"non-digit byte", "seg-000000000000000a.vmsp", false, 0},
		{"leading plus sign", "seg-+000000000000001.vmsp", false, 0},
		{"leading space", "seg- 000000000000001.vmsp", false, 0},
		{"trailing suffix", "seg-0000000000000001.vmsp.tmp", false, 0},
		{"wrong prefix", "bad.vmsp", false, 0},
		{"uppercase prefix", "SEG-0000000000000001.vmsp", false, 0},
		{"empty", "", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, ok := parseSegmentName(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("parseSegmentName(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if idx != tt.wantIdx {
				t.Fatalf("parseSegmentName(%q) idx = %d, want %d", tt.input, idx, tt.wantIdx)
			}
			if got := segmentName(idx); got != tt.input {
				t.Fatalf("segmentName(%d) = %q, want %q", idx, got, tt.input)
			}
		})
	}
}
