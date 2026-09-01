// ABOUTME: vmobs doctor: renders /host/status's preflight block as a human table
// ABOUTME: or --json passthrough. Exits 1 when Overall=fail (operational failure).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// dispatchDoctorCmd handles `vmobs doctor [--json]`.
func (c *client) dispatchDoctorCmd(args []string) int {
	// No subcommands; all flags come from the global --json flag already parsed.
	// Just run the doctor check.
	_ = args // no doctor-specific flags yet
	return c.doctor()
}

// doctor GETs /host/status and renders the preflight block.
// Exit 1 when Overall=fail (the daemon is operational; this is an op verdict).
// Exit 2 on transport failure. Exit 1 on structured API error.
func (c *client) doctor() int {
	status, body, err := c.do(http.MethodGet, "/api/v1/host/status", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		// Decode to extract the preflight block, then re-serialize it standalone.
		// If there's no preflight block, print the full response so the caller
		// can see there's no preflight wired.
		var full map[string]any
		if err := json.Unmarshal(body, &full); err != nil {
			return c.transport(fmt.Errorf("decode host/status: %w", err))
		}
		pf, ok := full["preflight"]
		if !ok {
			fmt.Fprintln(c.stderr, "vmobs: no preflight block in /host/status (preflight not wired in daemon)")
			return exitAPIError
		}
		out, err := json.MarshalIndent(pf, "", "  ")
		if err != nil {
			return c.transport(fmt.Errorf("re-marshal preflight: %w", err))
		}
		fmt.Fprintf(c.stdout, "%s\n", out)
		// Exit 1 when overall=fail: a failed doctor is an operational failure.
		pfMap, _ := pf.(map[string]any)
		if pfMap != nil {
			if overall, _ := pfMap["overall"].(string); overall == "fail" {
				return exitAPIError
			}
		}
		return exitOK
	}

	// Human rendering.
	var full map[string]any
	if err := json.Unmarshal(body, &full); err != nil {
		return c.transport(fmt.Errorf("decode host/status: %w", err))
	}
	pf, ok := full["preflight"]
	if !ok {
		fmt.Fprintln(c.stderr, "vmobs: no preflight block in /host/status (preflight not wired in daemon)")
		return exitAPIError
	}
	pfMap, ok := pf.(map[string]any)
	if !ok {
		return c.transport(fmt.Errorf("preflight block is not an object"))
	}
	return c.renderDoctorHuman(pfMap)
}

// renderDoctorHuman renders the preflight block as a table to stdout.
// Returns exitOK when Overall != fail, exitAPIError when fail.
func (c *client) renderDoctorHuman(pf map[string]any) int {
	overall, _ := pf["overall"].(string)
	arch, _ := pf["arch"].(string)
	kernel, _ := pf["kernel_release"].(string)
	ranAt, _ := pf["ran_at"].(string)

	fmt.Fprintf(c.stdout, "preflight  overall=%-15s arch=%s kernel=%s ran=%s\n",
		overall, arch, kernel, ranAt)
	fmt.Fprintf(c.stdout, "%-20s %-16s %s\n", "CHECK", "STATUS", "SUMMARY")
	fmt.Fprintln(c.stdout, strings.Repeat("-", 80))

	checks, _ := pf["checks"].([]any)
	for _, raw := range checks {
		ch, _ := raw.(map[string]any)
		if ch == nil {
			continue
		}
		id, _ := ch["id"].(string)
		chStatus, _ := ch["status"].(string)
		summary, _ := ch["summary"].(string)
		fmt.Fprintf(c.stdout, "%-20s %-16s %s\n", id, chStatus, summary)

		evidence, _ := ch["evidence"].([]any)
		for _, ev := range evidence {
			evStr, _ := ev.(string)
			if evStr != "" {
				fmt.Fprintf(c.stdout, "  %s\n", evStr)
			}
		}

		if rem, ok := ch["remediation"].(map[string]any); ok && rem != nil {
			cause, _ := rem["cause"].(string)
			action, _ := rem["action"].(string)
			if cause != "" || action != "" {
				fmt.Fprintf(c.stdout, "  remediation: cause=%s action=%s\n", cause, action)
			}
		}
	}

	if overall == "fail" {
		return exitAPIError
	}
	return exitOK
}
