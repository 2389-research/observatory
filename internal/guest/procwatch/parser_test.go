// ABOUTME: Tests bounded process record decoding and lifetime identity without live PID lookups.
// ABOUTME: Keeps lost, malformed and reused process evidence distinct from observed transitions.
package procwatch

import (
	"encoding/binary"
	"testing"
)

func sampleRecord() []byte {
	b := make([]byte, recordSize)
	binary.LittleEndian.PutUint32(b, 2)
	binary.LittleEndian.PutUint64(b[8:], 900)
	binary.LittleEndian.PutUint32(b[16:], 42)
	binary.LittleEndian.PutUint32(b[20:], 42)
	binary.LittleEndian.PutUint64(b[24:], 100)
	binary.LittleEndian.PutUint64(b[32:], 7)
	binary.LittleEndian.PutUint64(b[88:], 100)
	binary.LittleEndian.PutUint64(b[96:], 19)
	copy(b[64:], []byte{'a', 0xff, 'z'})
	return b
}
func TestDecodeKernelIdentityAndRawComm(t *testing.T) {
	e, err := decode(sampleRecord(), "boot-one")
	if err != nil {
		t.Fatal(err)
	}
	if e.Process.StartNS != "100" || e.Process.ExecGeneration != "7" || e.Process.BootID != "boot-one" || e.Process.TGID != 42 {
		t.Fatalf("identity: %+v", e.Process)
	}
	if e.CommRaw != "Yf96" || e.Kind != "proc.exec" {
		t.Fatalf("event: %+v", e)
	}
}
func TestDecodeRejectsMalformedRecords(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 95), make([]byte, 97), make([]byte, recordSize)} {
		if _, err := decode(b, "boot"); err == nil {
			t.Fatalf("accepted malformed record length %d", len(b))
		}
	}
}
func TestPIDReuseHasDifferentIdentity(t *testing.T) {
	a, _ := decode(sampleRecord(), "boot")
	b := sampleRecord()
	binary.LittleEndian.PutUint64(b[24:], 200)
	c, _ := decode(b, "boot")
	if a.Process == c.Process {
		t.Fatal("reused PID collapsed")
	}
}
func TestThreadExitDoesNotClaimGroupDeath(t *testing.T) {
	b := sampleRecord()
	binary.LittleEndian.PutUint32(b, 3)
	binary.LittleEndian.PutUint32(b[16:], 43)
	binary.LittleEndian.PutUint32(b[44:], 9)
	e, err := decode(b, "boot")
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsThread || !e.TaskExit || e.ExitWaitStatus == nil || *e.ExitWaitStatus != 9 {
		t.Fatalf("thread evidence: %+v", e)
	}
}
func TestIncompleteIdentityIsRejected(t *testing.T) {
	b := sampleRecord()
	binary.LittleEndian.PutUint32(b[84:], 1)
	if _, err := decode(b, "boot"); err == nil {
		t.Fatal("accepted failed kernel read")
	}
}
