// ABOUTME: Checks the shipped container entrypoint's ordering contract: the
// ABOUTME: init-auth one-shot must not depend on privileges its container lacks.
package deploy_test

import (
	"strings"
	"testing"
)

// TestInitAuthRunsBeforePrivd: minting the first operator credential writes to
// the credential store and needs nothing privileged, so scripts/vmobs-container
// runs it in a bare container -- no --cap-add, no --device, only the state
// volume. The entrypoint has to honour that by answering the subcommand before
// it starts privd.
//
// Measured 2026-09-06 with the branch below the privd block: init-auth never
// ran. privd's jail probe failed first with "could not enter a private mount
// namespace ... run the container with --cap-add SYS_ADMIN", the entrypoint
// exited 1, and no credential was minted -- a first-run operator is told to add
// a capability to a command that does not need one, and has no way to log in.
func TestInitAuthRunsBeforePrivd(t *testing.T) {
	s := readFile(t, entrypointPath)

	const (
		initAuthBranch = `if [ "${1:-}" = "init-auth" ]`
		privdStart     = "/usr/local/sbin/vmobs-privd \\"
	)
	initAuth := strings.Index(s, initAuthBranch)
	if initAuth < 0 {
		t.Fatalf("no init-auth branch in %s", entrypointPath)
	}
	privd := strings.Index(s, privdStart)
	if privd < 0 {
		t.Fatalf("no privd launch in %s", entrypointPath)
	}
	if initAuth > privd {
		t.Errorf("the init-auth branch is at byte %d, after privd starts at %d; "+
			"a bare init-auth container dies on privd's jail probe and mints nothing",
			initAuth, privd)
	}
}

// TestInitAuthDoesNotNeedTheKVMGroup: the same argument one step further. The
// kvm group block exists for vmobsd's arch_kvm preflight, which init-auth never
// runs, and a bare container has no /dev/kvm -- so reaching that block at all
// prints a warning about a device this invocation does not want, in front of an
// operator who is following the documented first-run step.
func TestInitAuthDoesNotNeedTheKVMGroup(t *testing.T) {
	s := readFile(t, entrypointPath)

	initAuth := strings.Index(s, `if [ "${1:-}" = "init-auth" ]`)
	kvmBlock := strings.Index(s, "if [ -c /dev/kvm ]")
	if initAuth < 0 || kvmBlock < 0 {
		t.Fatalf("entrypoint no longer has both an init-auth branch and a kvm block")
	}
	if initAuth > kvmBlock {
		t.Errorf("the init-auth branch is at byte %d, after the kvm group block at %d; "+
			"minting a credential warns about a missing device it does not use",
			initAuth, kvmBlock)
	}
}
