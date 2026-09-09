// ABOUTME: Portable flag-parsing tests for vmobs-privd; no linux requirement.
// ABOUTME: Tests parseFlags defaults and required-flag validation only.
package main

import (
	"strings"
	"testing"
)

func TestParseFlagsDefaults(t *testing.T) {
	flags, err := parseFlags([]string{
		"--allowed-uid", "1000",
		"--allowed-gid", "1000",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.socket != "/run/vmobs/privd.sock" {
		t.Errorf("socket default = %q; want %q", flags.socket, "/run/vmobs/privd.sock")
	}
	if flags.ledgerDir != "/run/vmobs/privd" {
		t.Errorf("ledger-dir default = %q; want %q", flags.ledgerDir, "/run/vmobs/privd")
	}
	if flags.stageRoot != "/srv/vmobs/stage" {
		t.Errorf("stage-root default = %q; want %q", flags.stageRoot, "/srv/vmobs/stage")
	}
	if flags.jailBase != "/srv/vmobs/jail" {
		t.Errorf("jail-base default = %q; want %q", flags.jailBase, "/srv/vmobs/jail")
	}
	if flags.firecracker != "/usr/local/bin/firecracker" {
		t.Errorf("firecracker default = %q; want %q", flags.firecracker, "/usr/local/bin/firecracker")
	}
	if flags.jailer != "/usr/local/bin/jailer" {
		t.Errorf("jailer default = %q; want %q", flags.jailer, "/usr/local/bin/jailer")
	}
}

func TestParseFlagsMissingAllowedUID(t *testing.T) {
	_, err := parseFlags([]string{"--allowed-gid", "1000"})
	if err == nil {
		t.Fatal("expected error for missing --allowed-uid; got nil")
	}
	if !strings.Contains(err.Error(), "allowed-uid") {
		t.Errorf("error %q should mention allowed-uid", err.Error())
	}
}

func TestParseFlagsMissingAllowedGID(t *testing.T) {
	_, err := parseFlags([]string{"--allowed-uid", "1000"})
	if err == nil {
		t.Fatal("expected error for missing --allowed-gid; got nil")
	}
	if !strings.Contains(err.Error(), "allowed-gid") {
		t.Errorf("error %q should mention allowed-gid", err.Error())
	}
}

func TestParseFlagsExplicitValues(t *testing.T) {
	flags, err := parseFlags([]string{
		"--allowed-uid", "5555",
		"--allowed-gid", "6666",
		"--socket", "/tmp/test.sock",
		"--ledger-dir", "/tmp/ledger",
		"--stage-root", "/tmp/stage",
		"--jail-base", "/tmp/jail",
		"--firecracker", "/usr/bin/firecracker",
		"--jailer", "/usr/bin/jailer",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.allowedUID != 5555 {
		t.Errorf("allowed-uid = %d; want 5555", flags.allowedUID)
	}
	if flags.allowedGID != 6666 {
		t.Errorf("allowed-gid = %d; want 6666", flags.allowedGID)
	}
	if flags.socket != "/tmp/test.sock" {
		t.Errorf("socket = %q; want /tmp/test.sock", flags.socket)
	}
	if flags.ledgerDir != "/tmp/ledger" {
		t.Errorf("ledger-dir = %q; want /tmp/ledger", flags.ledgerDir)
	}
	if flags.stageRoot != "/tmp/stage" {
		t.Errorf("stage-root = %q; want /tmp/stage", flags.stageRoot)
	}
	if flags.jailBase != "/tmp/jail" {
		t.Errorf("jail-base = %q; want /tmp/jail", flags.jailBase)
	}
}

func TestParseExplicitNetworkPolicyDirectory(t *testing.T) {
	flags, err := parseFlags([]string{"--allowed-uid", "1000", "--allowed-gid", "1000", "--network-policy-dir", "/etc/vmobs/network-policies"})
	if err != nil {
		t.Fatal(err)
	}
	if flags.policyDirectory != "/etc/vmobs/network-policies" {
		t.Fatal("policy directory not retained")
	}
}
