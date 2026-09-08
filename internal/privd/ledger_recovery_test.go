// ABOUTME: Ledger recovery refuses records that cannot prove which VM owns resources.
// ABOUTME: Malformed records must block claims rather than free potentially occupied identities.
package privd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerRejectsAmbiguousRecords(t *testing.T) {
	for _, contents := range []string{`{}`, `{"vm_id":"vm-neighbor","pid":0}`, `{"vm_id":"vm-owner","pid":-1}`} {
		t.Run(contents, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "vm-owner.json"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			l := newLedger(dir)
			if _, err := l.get("vm-owner"); err == nil {
				t.Error("get accepted ambiguous ownership")
			}
			if _, err := l.all(); err == nil {
				t.Error("claim scan accepted ambiguous ownership")
			}
		})
	}
}

func TestLedgerRecordDirectoryBlocksClaims(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "vm-owner.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := newLedger(dir).all(); err == nil {
		t.Fatal("unreadable ownership record was treated as free")
	}
}

func TestLedgerRefusesUntrustedRecordFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "writable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "vm-owner.json")
			data := []byte(`{"vm_id":"vm-owner","pid":0}`)
			if kind == "symlink" {
				target := filepath.Join(t.TempDir(), "record")
				if err := os.WriteFile(target, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, record); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(record, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(record, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := newLedger(dir).get("vm-owner"); err == nil {
				t.Fatal("untrusted ledger record accepted")
			}
			if _, err := newLedger(dir).all(); err == nil {
				t.Fatal("claim scan ignored untrusted record")
			}
		})
	}
}

func TestLedgerRejectsIncompleteProcessIdentity(t *testing.T) {
	for _, contents := range []string{
		`{"vm_id":"vm-owner","uid":30001,"gid":30001,"cid":10,"start_time":"123"}`,
		`{"vm_id":"vm-owner","pid":0,"uid":30001}`,
		`{"vm_id":"vm-owner","pid":0,"gid":30001}`,
		`{"vm_id":"vm-owner","pid":0,"cid":10}`,
		`{"vm_id":"vm-owner","pid":0,"start_time":"123"}`,
		`{"vm_id":"vm-owner","pid":0,"boot_id":"11111111-1111-4111-8111-111111111111"}`,
		`{"vm_id":"vm-owner","pid":0,"pid_namespace":"pid:[1]"}`,
		`{"vm_id":"vm-owner","pid":123,"uid":30001,"gid":30001,"cid":10}`,
		`{"vm_id":"vm-owner","pid":123,"uid":30001,"gid":30001,"cid":10,"start_time":"garbled"}`,
		`{"vm_id":"vm-owner","pid":123,"uid":30001,"gid":30001,"start_time":"123"}`,
	} {
		t.Run(contents, func(t *testing.T) {
			dir := t.TempDir()
			ledgerDir := filepath.Join(dir, "ledger")
			if err := os.Mkdir(ledgerDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ledgerDir, "vm-owner.json"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			jail := filepath.Join(dir, "jail")
			tree := filepath.Join(jail, "firecracker", "vm-owner", "root")
			if err := os.MkdirAll(tree, 0700); err != nil {
				t.Fatal(err)
			}
			s := NewServer(ServerCfg{LedgerDir: ledgerDir, Ops: &stubOps{jailBase: jail}})
			if _, err := s.ledger.get("vm-owner"); err == nil {
				t.Error("incomplete process ownership accepted")
			}
			if _, err := s.ledger.all(); err == nil {
				t.Error("claim scan accepted incomplete process ownership")
			}
			if resp := s.handleReleaseVM([]byte(`{"vm_id":"vm-owner"}`)); resp.OK {
				t.Error("release accepted incomplete process ownership")
			}
			if _, err := os.Stat(tree); err != nil {
				t.Errorf("ambiguous process jail was removed: %v", err)
			}
		})
	}
}

func TestLedgerAcceptsNetworkOnlyRecord(t *testing.T) {
	l := newLedger(t.TempDir())
	if err := l.put(VMEntry{VMID: "vm-owner", NetCIDR: "10.201.0.0/30"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.get("vm-owner"); err != nil {
		t.Fatal(err)
	}
}
