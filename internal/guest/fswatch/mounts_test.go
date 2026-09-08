// ABOUTME: Checks mount inventory preserves escaped names and refuses malformed data.
// ABOUTME: Coverage includes unsupported filesystems instead of silently dropping them.
package fswatch

import "testing"

func TestMountInventory(t *testing.T) {
	m, err := parseMounts("1 0 8:1 / / rw - ext4 /dev/vda rw\n2 1 0:4 / /a\\040b rw - tmpfs tmpfs rw\n")
	if err != nil || len(m) != 2 || m[1].Point != "/a b" || m[0].Type != "ext4" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := parseMounts("nonsense"); err == nil {
		t.Fatal("accepted invalid mountinfo")
	}
}

func TestCoverageLabelsAreBounded(t *testing.T) {
	label := coverageLabel(string(make([]byte, 4096)))
	if len(label) > 180 || label[len(label)-3:] != "..." {
		t.Fatalf("unbounded label length %d", len(label))
	}
}

func TestMountInventoryRetainsInvalidUTF8(t *testing.T) {
	m, err := parseMounts("1 0 8:1 / /bad\xff rw - ext4 /dev/vda rw\n")
	if err != nil {
		t.Fatal(err)
	}
	if m[0].PointBase64 != "L2JhZP8=" {
		t.Fatalf("lost raw mount name: %+v", m[0])
	}
}
