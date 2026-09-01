// ABOUTME: CLI handlers for the "run" subcommand family: submit, list, get,
// ABOUTME: conclude, report. --json parity with the API; typed exit codes.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
)

// dispatchRunCmd handles `vmobs run <subcmd> ...`.
func (c *client) dispatchRunCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs run submit|list|get|conclude|report ...")
		return exitUsage
	}
	switch args[0] {
	case "submit":
		return c.runSubmit(args[1:])
	case "list":
		return c.runList(args[1:])
	case "get":
		return c.runGet(args[1:])
	case "conclude":
		return c.runConclude(args[1:])
	case "report":
		return c.runReport(args[1:])
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown run subcommand %q\n", args[0])
		return exitUsage
	}
}

// --- run submit ---

// runSubmit handles `vmobs run submit --vm ID --goal TEXT --criteria TYPE
// --on-completion POLICY [--progress-events] [--idempotency-key K]`.
// All three of --vm, --goal, --criteria, --on-completion are required (exit 3
// if any are missing). API-owned validation (e.g. VM not running, R2) surfaces
// via the existing fail() path (exit 1).
func (c *client) runSubmit(args []string) int {
	fs := flag.NewFlagSet("vmobs run submit", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	vmID := fs.String("vm", "", "VM ID to attach the run to (required)")
	goal := fs.String("goal", "", "run goal text (required)")
	criteria := fs.String("criteria", "", "success criteria type: operator_verdict|guest_result|exec_exit_zero (required)")
	onCompletion := fs.String("on-completion", "", "what to do when the run concludes: keep_running|stop (required)")
	progressEvents := fs.Bool("progress-events", false, "emit run.progress events for guest progress submissions")
	ikey := fs.String("idempotency-key", "", "client-chosen idempotency key")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// CLI-level required-flag checks. API validation is the authority for
	// everything else (criteria values, on-completion values, VM state).
	if *vmID == "" {
		fmt.Fprintln(c.stderr, "vmobs: --vm is required")
		return exitUsage
	}
	if *goal == "" {
		fmt.Fprintln(c.stderr, "vmobs: --goal is required")
		return exitUsage
	}
	if *criteria == "" {
		fmt.Fprintln(c.stderr, "vmobs: --criteria is required")
		return exitUsage
	}
	if *onCompletion == "" {
		fmt.Fprintln(c.stderr, "vmobs: --on-completion is required")
		return exitUsage
	}

	reqBody := map[string]any{
		"goal": *goal,
		"success_criteria": map[string]any{
			"type": *criteria,
		},
		"on_completion":   *onCompletion,
		"progress_events": *progressEvents,
	}
	if *ikey != "" {
		reqBody["idempotency_key"] = *ikey
	}

	encoded, _ := json.Marshal(reqBody)
	path := "/api/v1/vms/" + url.PathEscape(*vmID) + "/runs"
	status, body, err := c.do("POST", path, bytes.NewReader(encoded))
	if err != nil {
		return c.transport(err)
	}
	if status != 201 {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode submit response: %w", err))
	}
	run, _ := resp["run"].(map[string]any)
	printRun(c.stdout, run)
	if resp["is_replay"] == true {
		fmt.Fprintln(c.stdout, "note: idempotency replay")
	}
	return exitOK
}

// --- run list ---

// runList handles `vmobs run list [--vm ID] [--phase P] [--after CURSOR] [--limit N]`.
func (c *client) runList(args []string) int {
	fs := flag.NewFlagSet("vmobs run list", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	vmID := fs.String("vm", "", "filter by VM ID")
	phase := fs.String("phase", "", "filter by phase (pending|running|concluding|succeeded|failed|inconclusive|aborted)")
	after := fs.String("after", "", "keyset cursor from previous page's next_after")
	limit := fs.Int("limit", 0, "page size (0 = daemon default)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	params := url.Values{}
	if *vmID != "" {
		params.Set("vm_id", *vmID)
	}
	if *phase != "" {
		params.Set("phase", *phase)
	}
	if *after != "" {
		params.Set("after", *after)
	}
	if *limit != 0 {
		params.Set("limit", fmt.Sprint(*limit))
	}
	path := "/api/v1/runs"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	status, body, err := c.do("GET", path, nil)
	if err != nil {
		return c.transport(err)
	}
	if status != 200 {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp struct {
		Runs      []map[string]any `json:"runs"`
		NextAfter string           `json:"next_after"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode run list: %w", err))
	}
	if len(resp.Runs) == 0 {
		fmt.Fprintln(c.stdout, "(no runs)")
		return exitOK
	}
	fmt.Fprintf(c.stdout, "%-36s  %-36s  %-14s  %-18s\n", "RUN ID", "VM ID", "PHASE", "CRITERIA")
	for _, run := range resp.Runs {
		runID, _ := run["run_id"].(string)
		vm, _ := run["vm_id"].(string)
		ph, _ := run["phase"].(string)
		cr, _ := run["criteria_type"].(string)
		fmt.Fprintf(c.stdout, "%-36s  %-36s  %-14s  %-18s\n", runID, vm, ph, cr)
	}
	if resp.NextAfter != "" {
		fmt.Fprintf(c.stdout, "next_after=%s\n", resp.NextAfter)
	}
	return exitOK
}

// --- run get ---

// runGet handles `vmobs run get <run-id>`.
func (c *client) runGet(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs run get RUN-ID")
		return exitUsage
	}
	runID := args[0]
	status, body, err := c.do("GET", "/api/v1/runs/"+url.PathEscape(runID), nil)
	if err != nil {
		return c.transport(err)
	}
	if status != 200 {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var run map[string]any
	if err := json.Unmarshal(body, &run); err != nil {
		return c.transport(fmt.Errorf("decode run: %w", err))
	}
	printRun(c.stdout, run)
	return exitOK
}

// --- run conclude ---

// runConclude handles `vmobs run conclude <run-id> (--verdict V [--reason R] | --abort --reason R)`.
// CLI validation: verdict and abort are mutually exclusive, and at least one must be set
// (exit 3). The API validates verdict values and criteria compatibility.
func (c *client) runConclude(args []string) int {
	fs := flag.NewFlagSet("vmobs run conclude", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	verdict := fs.String("verdict", "", "conclusion verdict: succeeded|failed")
	abort := fs.Bool("abort", false, "abort the run regardless of criteria type")
	reason := fs.String("reason", "", "human-readable reason for the conclusion")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// Run ID is the first non-flag arg. Per Go flag-package contract, all flags
	// must appear before positional args; the dispatch layer already consumed
	// "conclude" so rest[0] is the run ID.
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs run conclude [--verdict succeeded|failed | --abort] [--reason TEXT] RUN-ID")
		return exitUsage
	}
	runID := rest[0]

	hasVerdict := *verdict != ""
	hasAbort := *abort

	// Exactly one of verdict or abort must be set. Both or neither is a usage error.
	if hasVerdict && hasAbort {
		fmt.Fprintln(c.stderr, "vmobs: --verdict and --abort are mutually exclusive")
		return exitUsage
	}
	if !hasVerdict && !hasAbort {
		fmt.Fprintln(c.stderr, "vmobs: one of --verdict or --abort is required")
		return exitUsage
	}

	reqBody := map[string]any{}
	if hasVerdict {
		reqBody["verdict"] = *verdict
	}
	if hasAbort {
		reqBody["abort"] = true
	}
	if *reason != "" {
		reqBody["reason"] = *reason
	}

	encoded, _ := json.Marshal(reqBody)
	path := "/api/v1/runs/" + url.PathEscape(runID) + "/conclude"
	status, body, err := c.do("POST", path, bytes.NewReader(encoded))
	if err != nil {
		return c.transport(err)
	}
	if status != 200 {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode conclude response: %w", err))
	}
	run, _ := resp["run"].(map[string]any)
	printRun(c.stdout, run)
	return exitOK
}

// --- run report ---

// runReport handles `vmobs run report <run-id>`. Returns 0 for all three statuses
// (generated/pending/failed) — the report status is not an error, just a state.
func (c *client) runReport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs run report RUN-ID")
		return exitUsage
	}
	runID := args[0]
	status, body, err := c.do("GET", "/api/v1/runs/"+url.PathEscape(runID)+"/report", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != 200 {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode report response: %w", err))
	}

	rptStatus, _ := resp["status"].(string)
	switch rptStatus {
	case "generated":
		generatedAt, _ := resp["generated_at"].(string)
		digest, _ := resp["digest"].(string)
		fmt.Fprintf(c.stdout, "status:       generated\n")
		fmt.Fprintf(c.stdout, "generated_at: %s\n", generatedAt)
		fmt.Fprintf(c.stdout, "digest:       %s\n", digest)
		if rpt, ok := resp["report"].(map[string]any); ok {
			if phaseStr, _ := rpt["phase"].(string); phaseStr != "" {
				fmt.Fprintf(c.stdout, "phase:        %s\n", phaseStr)
			}
		}
	case "pending":
		fmt.Fprintf(c.stdout, "status:   pending\n")
		if opID, ok := resp["operation_id"].(string); ok && opID != "" {
			fmt.Fprintf(c.stdout, "op:       %s\n", opID)
		}
		fmt.Fprintf(c.stdout, "note:     report generation in progress; retry shortly\n")
	case "failed":
		opID, _ := resp["operation_id"].(string)
		fmt.Fprintf(c.stdout, "status:   failed\n")
		if opID != "" {
			fmt.Fprintf(c.stdout, "op:       %s\n", opID)
		}
		fmt.Fprintf(c.stdout, "note:     report generation failed; a retry has been enqueued\n")
	default:
		fmt.Fprintf(c.stdout, "status: %s\n", rptStatus)
	}
	return exitOK
}

// --- rendering ---

// printRun renders a run object in human-readable multi-line form. Used by
// submit, get, and conclude to present a consistent view.
func printRun(w interface{ Write([]byte) (int, error) }, run map[string]any) {
	field := func(k string) string {
		v, _ := run[k].(string)
		return v
	}
	fmt.Fprintf(w, "run:          %s\n", field("run_id"))
	fmt.Fprintf(w, "vm:           %s\n", field("vm_id"))
	fmt.Fprintf(w, "phase:        %s\n", field("phase"))
	fmt.Fprintf(w, "criteria:     %s\n", field("criteria_type"))
	fmt.Fprintf(w, "on_complete:  %s\n", field("on_completion"))
	fmt.Fprintf(w, "goal:         %s\n", field("goal"))
	if outcome, ok := run["outcome"].(map[string]any); ok && outcome != nil {
		by, _ := outcome["evaluated_by"].(string)
		reason, _ := outcome["reason"].(string)
		fmt.Fprintf(w, "outcome:      %s (by %s)\n", field("phase"), by)
		if reason != "" {
			fmt.Fprintf(w, "reason:       %s\n", reason)
		}
	}
	if links, ok := run["links"].(map[string]any); ok {
		if reportLink, _ := links["report"].(string); reportLink != "" {
			fmt.Fprintf(w, "report:       %s\n", reportLink)
		}
	}
}
