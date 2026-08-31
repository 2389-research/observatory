// ABOUTME: vmobs situation / attention / attention ack: the scriptable poll
// ABOUTME: loop over the operator working set, human and --json from one response.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type wireAttentionItem struct {
	AttentionID  string  `json:"attention_id"`
	Cursor       string  `json:"cursor"`
	Severity     string  `json:"severity"`
	Kind         string  `json:"kind"`
	VMID         *string `json:"vm_id"`
	Summary      string  `json:"summary"`
	SystemAction string  `json:"system_action"`
	Count        string  `json:"count"`
	Acked        bool    `json:"acked"`
}

func renderAttentionLine(w *client, it wireAttentionItem) {
	scope := "host"
	if it.VMID != nil {
		scope = *it.VMID
	}
	fmt.Fprintf(w.stdout, "%s\t%s\t%s\t%s\tcount=%s\tacked=%v\t%s\n",
		it.AttentionID, it.Severity, it.Kind, scope, it.Count, it.Acked, it.Summary)
}

func (c *client) situation(args []string) int {
	fs := flag.NewFlagSet("vmobs situation", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	since := fs.String("since", "", "only report change past this cursor (as_of of a previous call)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	path := "/api/v1/situation"
	if *since != "" {
		path += "?since=" + url.QueryEscape(*since)
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
		AsOfCursor  string `json:"as_of_cursor"`
		SinceCursor string `json:"since_cursor"`
		Quiet       bool   `json:"quiet"`
		Host        struct {
			VMsRunning int `json:"vms_running"`
			VMsTotal   int `json:"vms_total"`
			Watch      struct {
				TriggerClassesActive []string `json:"trigger_classes_active"`
				SensorsDegraded      int      `json:"sensors_degraded"`
			} `json:"watch"`
		} `json:"host"`
		AttentionHead []wireAttentionItem `json:"attention_head"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode situation: %v\n", err)
		return exitTransport
	}
	line := fmt.Sprintf("quiet=%v as_of=%s", resp.Quiet, resp.AsOfCursor)
	if resp.SinceCursor != "" {
		line += " since=" + resp.SinceCursor
	}
	fmt.Fprintln(c.stdout, line)
	fmt.Fprintf(c.stdout, "watch: %s (sensors_degraded=%d)\n",
		strings.Join(resp.Host.Watch.TriggerClassesActive, ", "), resp.Host.Watch.SensorsDegraded)
	fmt.Fprintf(c.stdout, "vms: %d/%d running\n", resp.Host.VMsRunning, resp.Host.VMsTotal)
	fmt.Fprintf(c.stdout, "attention head (%d):\n", len(resp.AttentionHead))
	for _, it := range resp.AttentionHead {
		renderAttentionLine(c, it)
	}
	return exitOK
}

func (c *client) attention(args []string) int {
	fs := flag.NewFlagSet("vmobs attention", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	all := fs.Bool("all", false, "include acknowledged items")
	after := fs.Int64("after", 0, "resume after this attention id (next_after of a previous page)")
	limit := fs.Int("limit", 0, "page size (default and max come from the daemon)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	params := url.Values{}
	if *all {
		params.Set("include_acked", "true")
	}
	if *after != 0 {
		params.Set("after", fmt.Sprint(*after))
	}
	if *limit != 0 {
		params.Set("limit", fmt.Sprint(*limit))
	}
	path := "/api/v1/attention"
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
		Items     []wireAttentionItem `json:"items"`
		NextAfter string              `json:"next_after"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode attention list: %v\n", err)
		return exitTransport
	}
	for _, it := range resp.Items {
		renderAttentionLine(c, it)
	}
	fmt.Fprintf(c.stdout, "next_after=%s count=%d\n", resp.NextAfter, len(resp.Items))
	return exitOK
}

func (c *client) attentionAck(args []string) int {
	if len(args) != 1 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(c.stderr, "usage: vmobs attention ack ATT-ID")
		return exitUsage
	}
	status, body, err := c.do(http.MethodPost,
		"/api/v1/attention/"+url.PathEscape(args[0])+"/ack", strings.NewReader("{}"))
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
	var it wireAttentionItem
	if err := json.Unmarshal(body, &it); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode ack response: %v\n", err)
		return exitTransport
	}
	fmt.Fprintf(c.stdout, "acked %s (%s %s)\n", it.AttentionID, it.Severity, it.Kind)
	return exitOK
}
