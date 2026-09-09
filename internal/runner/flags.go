// ABOUTME: ParseFlags parses the vmobs-runner command-line argv into a Config.
// ABOUTME: Validates all flags are present and --vmm-starttime is decimal digits.
package runner

import (
	"flag"
	"fmt"
	"time"
	"unicode"

	"github.com/2389-research/observatory/internal/privd"
)

// ParseFlags parses args into a Config. It returns an error when required flags
// are missing or --vmm-starttime contains non-decimal characters.
// name is the program name (used in flag.FlagSet error messages).
func ParseFlags(name string, args []string) (Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)

	networkObservers := fs.String("network-observers", "", "binding for the inherited network observer descriptors (JSON)")
	networkUnavailableReason := fs.String("network-unavailable-reason", "", "why no network observers were acquired")
	vmID := fs.String("vm-id", "", "VM identifier")
	bootID := fs.String("boot-id", "", "boot UUID")
	instanceID := fs.String("instance-id", "", "runner instance UUID")
	udsPath := fs.String("uds", "", "path to the VM vsock UDS (v.sock)")
	tokenFile := fs.String("token-file", "", "path to the capability token file")
	spoolDir := fs.String("spool-dir", "", "spool directory for this VM")
	stateFile := fs.String("state-file", "", "path to runner-state.json")
	ctlSock := fs.String("ctl-sock", "", "path for the control unix socket")
	vmmPID := fs.Int("vmm-pid", 0, "VMM process PID")
	vmmStartTime := fs.String("vmm-starttime", "", "VMM /proc starttime (decimal ticks)")
	pingInterval := fs.Duration("ping-interval", 5*time.Second, "period between guest pings")

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("runner flags: %w", err)
	}

	// Validate all required flags are non-empty / non-zero.
	missing := []string{}
	if *vmID == "" {
		missing = append(missing, "--vm-id")
	}
	if *bootID == "" {
		missing = append(missing, "--boot-id")
	}
	if *instanceID == "" {
		missing = append(missing, "--instance-id")
	}
	if *udsPath == "" {
		missing = append(missing, "--uds")
	}
	if *tokenFile == "" {
		missing = append(missing, "--token-file")
	}
	if *spoolDir == "" {
		missing = append(missing, "--spool-dir")
	}
	if *stateFile == "" {
		missing = append(missing, "--state-file")
	}
	if *ctlSock == "" {
		missing = append(missing, "--ctl-sock")
	}
	if *vmmPID == 0 {
		missing = append(missing, "--vmm-pid")
	}
	if *vmmStartTime == "" {
		missing = append(missing, "--vmm-starttime")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("runner flags: missing required flags: %v", missing)
	}

	// --vmm-starttime must be decimal digits only.
	if !isDecimalDigits(*vmmStartTime) {
		return Config{}, fmt.Errorf("runner flags: --vmm-starttime must be decimal digits, got %q", *vmmStartTime)
	}

	// Exactly one of the two network flags is set. A runner with neither would
	// have no observers and no reason to publish for their absence.
	if (*networkObservers == "") == (*networkUnavailableReason == "") {
		return Config{}, fmt.Errorf("runner flags: exactly one of --network-observers and --network-unavailable-reason is required")
	}
	var bundle *privd.NetworkObserverBundle
	if *networkObservers != "" {
		decoded, err := privd.DecodeObserverBinding([]byte(*networkObservers))
		if err != nil {
			return Config{}, fmt.Errorf("runner flags: --network-observers: %w", err)
		}
		// The binding is only self-consistent. This runner labels every record
		// from --vm-id and --boot-id but scopes its readers from the binding, so
		// a binding for another VM or boot would observe one VM and name another.
		if decoded.Binding.VMID != *vmID || decoded.Binding.GuestBootID != *bootID {
			return Config{}, fmt.Errorf("runner flags: --network-observers binds vm %q boot %q, not the requested %q %q",
				decoded.Binding.VMID, decoded.Binding.GuestBootID, *vmID, *bootID)
		}
		bundle = decoded
	}
	if len(*networkUnavailableReason) > MaxNetworkReasonBytes {
		return Config{}, fmt.Errorf("runner flags: --network-unavailable-reason exceeds %d bytes", MaxNetworkReasonBytes)
	}

	return Config{
		VMID:                     *vmID,
		NetworkObservers:         bundle,
		NetworkUnavailableReason: *networkUnavailableReason,
		BootID:                   *bootID,
		InstanceID:               *instanceID,
		UDSPath:                  *udsPath,
		TokenFile:                *tokenFile,
		SpoolDir:                 *spoolDir,
		StateFile:                *stateFile,
		CtlSock:                  *ctlSock,
		VMMPID:                   *vmmPID,
		VMMStartTime:             *vmmStartTime,
		PingInterval:             *pingInterval,
	}, nil
}

// isDecimalDigits returns true when s is non-empty and consists only of ASCII digits.
func isDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) || r > '9' {
			return false
		}
	}
	return true
}
