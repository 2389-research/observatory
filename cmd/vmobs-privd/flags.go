// ABOUTME: Flag definitions and parsing for vmobs-privd; portable (no build tag).
// ABOUTME: main_linux.go calls parseFlags; main_other.go doesn't run real code.
package main

import (
	"flag"
	"fmt"
)

// privdFlags holds the parsed command-line configuration for vmobs-privd.
type privdFlags struct {
	socket      string
	ledgerDir   string
	stageRoot   string
	jailBase    string
	firecracker string
	jailer      string
	allowedUID  int
	allowedGID  int
}

// parseFlags parses argv (os.Args[1:]) and returns the resulting privdFlags.
// Returns an error when required flags are absent or flag parsing fails.
func parseFlags(argv []string) (privdFlags, error) {
	fs := flag.NewFlagSet("vmobs-privd", flag.ContinueOnError)

	socket := fs.String("socket", "/run/vmobs/privd.sock", "unix socket path")
	ledgerDir := fs.String("ledger-dir", "/run/vmobs/privd", "per-VM ledger directory")
	stageRoot := fs.String("stage-root", "/srv/vmobs/stage", "approved root for VM stage directories")
	jailBase := fs.String("jail-base", "/srv/vmobs/jail", "root for jailer workdirs")
	firecracker := fs.String("firecracker", "/usr/local/bin/firecracker", "path to firecracker binary")
	jailer := fs.String("jailer", "/usr/local/bin/jailer", "path to jailer binary")
	allowedUID := fs.Int("allowed-uid", 0, "required: UID whose connections are served (from $SUDO_UID)")
	allowedGID := fs.Int("allowed-gid", 0, "required: GID that owns the socket (from $SUDO_GID)")

	// Sentinel: -1 signals "not provided" since 0 is not a valid user UID in our range.
	// We use a pair of booleans instead to avoid coupling to uid semantics.
	uidSet := false
	gidSet := false
	fs.Visit(func(f *flag.Flag) {}) // dummy to trigger parse-time visit below

	if err := fs.Parse(argv); err != nil {
		return privdFlags{}, err
	}

	// Determine which flags were explicitly set.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "allowed-uid":
			uidSet = true
		case "allowed-gid":
			gidSet = true
		}
	})

	if !uidSet {
		return privdFlags{}, fmt.Errorf("--allowed-uid is required")
	}
	if !gidSet {
		return privdFlags{}, fmt.Errorf("--allowed-gid is required")
	}

	return privdFlags{
		socket:      *socket,
		ledgerDir:   *ledgerDir,
		stageRoot:   *stageRoot,
		jailBase:    *jailBase,
		firecracker: *firecracker,
		jailer:      *jailer,
		allowedUID:  *allowedUID,
		allowedGID:  *allowedGID,
	}, nil
}
