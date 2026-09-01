// ABOUTME: CLI handlers for vm, operation, template, and host subcommands.
// ABOUTME: Each has --json parity; human output renders the same API data.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// --- dispatch helpers ---

// dispatchVMCmd handles `vmobs vm <subcmd> ...`.
func (c *client) dispatchVMCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs vm list|get|create|action|delete ...")
		return exitUsage
	}
	switch args[0] {
	case "list":
		return c.vmList(args[1:])
	case "get":
		return c.vmGet(args[1:])
	case "create":
		return c.vmCreate(args[1:])
	case "action":
		return c.vmAction(args[1:])
	case "delete":
		return c.vmDelete(args[1:])
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown vm subcommand %q\n", args[0])
		return exitUsage
	}
}

// dispatchOperationCmd handles `vmobs operation <subcmd> ...`.
func (c *client) dispatchOperationCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs operation get OP-ID")
		return exitUsage
	}
	switch args[0] {
	case "get":
		return c.operationGet(args[1:])
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown operation subcommand %q\n", args[0])
		return exitUsage
	}
}

// dispatchTemplateCmd handles `vmobs template <subcmd> ...`.
func (c *client) dispatchTemplateCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs template list")
		return exitUsage
	}
	switch args[0] {
	case "list":
		return c.templateList()
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown template subcommand %q\n", args[0])
		return exitUsage
	}
}

// dispatchHostCmd handles `vmobs host <subcmd> ...`.
func (c *client) dispatchHostCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs host status")
		return exitUsage
	}
	switch args[0] {
	case "status":
		return c.hostStatus()
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown host subcommand %q\n", args[0])
		return exitUsage
	}
}

// --- vm list ---

func (c *client) vmList(args []string) int {
	fs := flag.NewFlagSet("vmobs vm list", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	after := fs.String("after", "", "resume after cursor (row_id of last item)")
	limit := fs.Int("limit", 0, "page size")
	state := fs.String("state", "", "filter by observed state, comma-separated for multiple (--state stopped,failed)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	params := url.Values{}
	if *after != "" {
		params.Set("after", *after)
	}
	if *limit != 0 {
		params.Set("limit", fmt.Sprint(*limit))
	}
	// state is comma-joined for simplicity; the API accepts repeated ?state= params.
	for _, s := range strings.Split(*state, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			params.Add("state", s)
		}
	}
	path := "/api/v1/vms"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	status, body, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp struct {
		VMs       []map[string]any `json:"vms"`
		NextAfter string           `json:"next_after"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode vm list: %w", err))
	}
	if len(resp.VMs) == 0 {
		fmt.Fprintln(c.stdout, "(no VMs)")
		return exitOK
	}
	fmt.Fprintf(c.stdout, "%-36s  %-20s  %-12s  %-20s\n", "VM ID", "NAME", "STATE", "TEMPLATE")
	for _, vm := range resp.VMs {
		vmID, _ := vm["vm_id"].(string)
		name, _ := vm["name"].(string)
		state, _ := vm["observed_state"].(string)
		tplID, _ := vm["template_id"].(string)
		fmt.Fprintf(c.stdout, "%-36s  %-20s  %-12s  %-20s\n", vmID, name, state, tplID)
	}
	if resp.NextAfter != "" {
		fmt.Fprintf(c.stdout, "next_after=%s\n", resp.NextAfter)
	}
	return exitOK
}

// --- vm get ---

func (c *client) vmGet(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs vm get VM-ID")
		return exitUsage
	}
	vmID := args[0]
	status, body, err := c.do(http.MethodGet, "/api/v1/vms/"+url.PathEscape(vmID), nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var vm map[string]any
	if err := json.Unmarshal(body, &vm); err != nil {
		return c.transport(fmt.Errorf("decode vm: %w", err))
	}
	printVM(c.stdout, vm)
	return exitOK
}

// printVM renders a vm object in human-readable multi-line form.
func printVM(w io.Writer, vm map[string]any) {
	field := func(k string) string {
		v, _ := vm[k].(string)
		return v
	}
	fmt.Fprintf(w, "vm:        %s\n", field("vm_id"))
	fmt.Fprintf(w, "name:      %s\n", field("name"))
	fmt.Fprintf(w, "state:     %s (desired: %s)\n", field("observed_state"), field("desired_state"))
	fmt.Fprintf(w, "revision:  %s\n", field("revision"))
	fmt.Fprintf(w, "template:  %s (%s)\n", field("template_id"), field("template_digest"))
	if res, ok := vm["resources"].(map[string]any); ok {
		vcpu, _ := res["vcpu_count"].(float64)
		mem, _ := res["memory_mib"].(float64)
		root, _ := res["root_disk_mib"].(float64)
		ws, _ := res["workspace_disk_mib"].(float64)
		fmt.Fprintf(w, "resources: %.0f vCPU / %.0f MiB RAM / %.0f MiB root / %.0f MiB workspace\n",
			vcpu, mem, root, ws)
	}
	fmt.Fprintf(w, "owner:     %s\n", field("owner"))
	labels := ""
	if lm, ok := vm["labels"].(map[string]any); ok && len(lm) > 0 {
		parts := make([]string, 0, len(lm))
		for k, v := range lm {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		sort.Strings(parts)
		labels = strings.Join(parts, ", ")
	} else {
		labels = "(none)"
	}
	fmt.Fprintf(w, "labels:    %s\n", labels)
	if links, ok := vm["links"].(map[string]any); ok {
		if ev, _ := links["events"].(string); ev != "" {
			fmt.Fprintf(w, "events:    %s\n", ev)
		}
	}
	if f, ok := vm["failure"].(map[string]any); ok && f != nil {
		stage, _ := f["stage"].(string)
		reason, _ := f["reason"].(string)
		fmt.Fprintf(w, "failure:   stage=%s reason=%s\n", stage, reason)
	}
}

// --- vm create ---

func (c *client) vmCreate(args []string) int {
	fs := flag.NewFlagSet("vmobs vm create", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	templateID := fs.String("template", "", "approved template ID (required)")
	ikey := fs.String("idempotency-key", "", "client-chosen idempotency key")
	vcpu := fs.Int("vcpu", 0, "vCPU count (0 = daemon default)")
	memMiB := fs.Int64("memory", 0, "memory MiB (0 = daemon default)")
	rootMiB := fs.Int64("root-disk", 0, "root disk MiB (0 = daemon default)")
	wsMiB := fs.Int64("workspace-disk", 0, "workspace disk MiB (0 = daemon default)")
	// Run attachment flags: all-or-none (goal + criteria + on-completion together).
	runGoal := fs.String("run-goal", "", "launch-attached run: goal text")
	runCriteria := fs.String("run-criteria", "", "launch-attached run: criteria type (operator_verdict|guest_result|exec_exit_zero)")
	runOnCompletion := fs.String("run-on-completion", "", "launch-attached run: on_completion policy (keep_running|stop)")
	runProgressEvents := fs.Bool("run-progress-events", false, "launch-attached run: emit run.progress events")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs vm create --template ID [flags] NAME")
		return exitUsage
	}
	if *templateID == "" {
		fmt.Fprintln(c.stderr, "vmobs: --template is required")
		return exitUsage
	}
	name := rest[0]

	// All-or-none validation for run flags: providing any strict subset is a
	// usage error. The API is the authority for value validation (criteria type,
	// on-completion value, R2 refusal). We only enforce presence here.
	runFlagCount := 0
	if *runGoal != "" {
		runFlagCount++
	}
	if *runCriteria != "" {
		runFlagCount++
	}
	if *runOnCompletion != "" {
		runFlagCount++
	}
	if runFlagCount > 0 && runFlagCount < 3 {
		fmt.Fprintln(c.stderr, "vmobs: --run-goal, --run-criteria, and --run-on-completion must all be set together")
		return exitUsage
	}

	reqBody := map[string]any{
		"name":        name,
		"template_id": *templateID,
	}
	if *ikey != "" {
		reqBody["idempotency_key"] = *ikey
	}
	if *vcpu != 0 {
		reqBody["vcpu_count"] = *vcpu
	}
	if *memMiB != 0 {
		reqBody["memory_mib"] = *memMiB
	}
	if *rootMiB != 0 {
		reqBody["root_disk_mib"] = *rootMiB
	}
	if *wsMiB != 0 {
		reqBody["workspace_disk_mib"] = *wsMiB
	}
	if runFlagCount == 3 {
		reqBody["run"] = map[string]any{
			"goal": *runGoal,
			"success_criteria": map[string]any{
				"type": *runCriteria,
			},
			"on_completion":   *runOnCompletion,
			"progress_events": *runProgressEvents,
		}
	}

	encoded, _ := json.Marshal(reqBody)
	status, body, err := c.do(http.MethodPost, "/api/v1/vms", bytes.NewReader(encoded))
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusCreated {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode create response: %w", err))
	}
	vm, _ := resp["vm"].(map[string]any)
	op, _ := resp["operation"].(map[string]any)
	vmID, _ := vm["vm_id"].(string)
	opID, _ := op["operation_id"].(string)
	opState, _ := op["state"].(string)
	fmt.Fprintf(c.stdout, "created %s  %s (%s)\n", vmID, opID, opState)
	return exitOK
}

// --- vm action ---

func (c *client) vmAction(args []string) int {
	fs := flag.NewFlagSet("vmobs vm action", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	revision := fs.String("revision", "", "expected revision (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintln(c.stderr, "usage: vmobs vm action VM-ID ACTION --revision N")
		return exitUsage
	}
	if *revision == "" {
		fmt.Fprintln(c.stderr, "vmobs: --revision is required")
		return exitUsage
	}
	vmID, action := rest[0], rest[1]

	reqBody, _ := json.Marshal(map[string]any{
		"action":            action,
		"expected_revision": *revision,
	})
	status, body, err := c.do(http.MethodPost,
		"/api/v1/vms/"+url.PathEscape(vmID)+"/actions", bytes.NewReader(reqBody))
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode action response: %w", err))
	}
	vm, _ := resp["vm"].(map[string]any)
	op, _ := resp["operation"].(map[string]any)
	vmID2, _ := vm["vm_id"].(string)
	opID, _ := op["operation_id"].(string)
	opState, _ := op["state"].(string)
	newState, _ := vm["observed_state"].(string)
	fmt.Fprintf(c.stdout, "%s on %s  %s (%s)\n", action, vmID2, opID, opState)
	if newState != "" {
		fmt.Fprintf(c.stdout, "state now: %s\n", newState)
	}
	return exitOK
}

// --- vm delete ---

func (c *client) vmDelete(args []string) int {
	fs := flag.NewFlagSet("vmobs vm delete", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	force := fs.Bool("force", false, "force-stop and delete even if VM is running")
	revision := fs.String("revision", "", "expected revision (optional)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs vm delete VM-ID [--force] [--revision N]")
		return exitUsage
	}
	vmID := rest[0]
	params := url.Values{}
	if *force {
		params.Set("force", "true")
	}
	if *revision != "" {
		params.Set("expected_revision", *revision)
	}
	path := "/api/v1/vms/" + url.PathEscape(vmID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	status, body, err := c.do(http.MethodDelete, path, nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode delete response: %w", err))
	}
	vm, _ := resp["vm"].(map[string]any)
	vmID2, _ := vm["vm_id"].(string)
	state, _ := vm["observed_state"].(string)
	fmt.Fprintf(c.stdout, "deleted %s (state: %s)\n", vmID2, state)
	return exitOK
}

// --- operation get ---

func (c *client) operationGet(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs operation get OP-ID")
		return exitUsage
	}
	opID := args[0]
	status, body, err := c.do(http.MethodGet, "/api/v1/operations/"+url.PathEscape(opID), nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var op map[string]any
	if err := json.Unmarshal(body, &op); err != nil {
		return c.transport(fmt.Errorf("decode operation: %w", err))
	}
	printOperation(c.stdout, op)
	return exitOK
}

// printOperation renders a single operation object in human form.
func printOperation(w io.Writer, op map[string]any) {
	opID, _ := op["operation_id"].(string)
	kind, _ := op["kind"].(string)
	phase, _ := op["phase"].(string)
	state, _ := op["state"].(string)
	attempt, _ := op["attempt"].(float64)
	vmID := ""
	if v, ok := op["vm_id"].(string); ok {
		vmID = " vm=" + v
	}
	fmt.Fprintf(w, "%s  %s%s  %s/%s  attempt=%.0f\n", opID, kind, vmID, phase, state, attempt)
	if errObj, ok := op["error"].(map[string]any); ok && errObj != nil {
		cause, _ := errObj["cause"].(string)
		msg, _ := errObj["message"].(string)
		fmt.Fprintf(w, "  error: %s — %s\n", cause, msg)
	}
}

// --- template list ---

func (c *client) templateList() int {
	status, body, err := c.do(http.MethodGet, "/api/v1/templates", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp struct {
		Templates []map[string]any `json:"templates"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode templates: %w", err))
	}
	if len(resp.Templates) == 0 {
		fmt.Fprintln(c.stdout, "(no approved templates)")
		return exitOK
	}
	fmt.Fprintf(c.stdout, "%-20s  %-30s  %s\n", "TEMPLATE ID", "DESCRIPTION", "DIGEST")
	for _, tpl := range resp.Templates {
		id, _ := tpl["template_id"].(string)
		desc, _ := tpl["description"].(string)
		digest, _ := tpl["digest"].(string)
		// Show first 16 chars of digest for readability.
		short := digest
		if len(short) > 23 {
			short = short[:23] + "…"
		}
		fmt.Fprintf(c.stdout, "%-20s  %-30s  %s\n", id, desc, short)
	}
	return exitOK
}

// --- host status ---

func (c *client) hostStatus() int {
	status, body, err := c.do(http.MethodGet, "/api/v1/host/status", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return c.transport(fmt.Errorf("decode host/status: %w", err))
	}

	// runtime block
	if rt, ok := resp["runtime"].(map[string]any); ok {
		avail, _ := rt["available"].(bool)
		reason, _ := rt["reason"].(string)
		if avail {
			fmt.Fprintln(c.stdout, "runtime: available")
		} else {
			fmt.Fprintf(c.stdout, "runtime: unavailable (%s)\n", reason)
		}
	}

	// capacity block
	if cap, ok := resp["capacity"].(map[string]any); ok {
		fmtMiB := func(key string) float64 {
			v, _ := cap[key].(float64)
			return v
		}
		usedMem := fmtMiB("reserved_memory_mib")
		usableMem := fmtMiB("usable_memory_mib")
		usedVCPU, _ := cap["reserved_vcpu"].(float64)
		usableVCPU, _ := cap["usable_vcpu"].(float64)
		activVMs, _ := cap["active_vms"].(float64)
		fmt.Fprintf(c.stdout, "memory:  %.0f/%.0f MiB used\n", usedMem, usableMem)
		fmt.Fprintf(c.stdout, "vcpu:    %.1f/%.1f used\n", usedVCPU, usableVCPU)
		fmt.Fprintf(c.stdout, "vms:     %.0f active\n", activVMs)
	}

	// vm state counts
	if vms, ok := resp["vms"].(map[string]any); ok && len(vms) > 0 {
		states := make([]string, 0, len(vms))
		for s := range vms {
			states = append(states, s)
		}
		sort.Strings(states)
		parts := make([]string, 0, len(states))
		for _, s := range states {
			count, _ := vms[s].(float64)
			parts = append(parts, fmt.Sprintf("%s=%.0f", s, count))
		}
		fmt.Fprintf(c.stdout, "states:  %s\n", strings.Join(parts, " "))
	}
	return exitOK
}
