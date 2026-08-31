// ABOUTME: vmobs: operator CLI for vmobsd. Every command has --json parity with
// ABOUTME: the API; human output renders the same data. Exit codes are typed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/events"
)

// Exit codes are part of the CLI contract (SPEC §14.1): scripts branch on them.
const (
	exitOK        = 0 // request succeeded
	exitAPIError  = 1 // the API answered with a structured error
	exitTransport = 2 // no structured answer: connection, timeout, or garbage
	exitUsage     = 3 // the invocation itself was wrong
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func defaultBase() string {
	if env := os.Getenv("VMOBS_API"); env != "" {
		return env
	}
	return "http://127.0.0.1:8787"
}

func usage(w io.Writer) {
	fmt.Fprint(w, `vmobs — operator CLI for the Firecracker Observatory daemon

usage: vmobs [--api URL] [--json] <command> [flags]

commands:
  meta                      capability manifest of the running daemon
  events [--vm ID] [--kind K] [--after CURSOR] [--limit N]
                            keyset-paged historical events
  situation [--since CURSOR]
                            bounded snapshot: watch scope, attention head, as_of cursor
  attention [--all] [--after N] [--limit N]
                            the attention queue (--all includes acknowledged items)
  attention ack ATT-ID      acknowledge one item; durable and idempotent
  api [-d BODY] METHOD PATH raw authenticated request, e.g. api GET /api/v1/meta

flags:
  --api URL   daemon base URL (default $VMOBS_API or http://127.0.0.1:8787)
  --json      print the API's JSON verbatim instead of human rendering

exit codes: 0 success, 1 structured API failure, 2 transport failure, 3 usage error
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vmobs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	apiBase := fs.String("api", defaultBase(), "daemon base URL")
	jsonOut := fs.Bool("json", false, "print API JSON verbatim")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	parsed, err := url.Parse(*apiBase)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		fmt.Fprintf(stderr, "vmobs: --api %q is not a URL\n", *apiBase)
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return exitUsage
	}

	c := &client{
		base:   strings.TrimRight(*apiBase, "/"),
		json:   *jsonOut,
		stdout: stdout,
		stderr: stderr,
	}
	switch rest[0] {
	case "meta":
		return c.meta()
	case "events":
		return c.events(rest[1:])
	case "situation":
		return c.situation(rest[1:])
	case "attention":
		if len(rest) > 1 && rest[1] == "ack" {
			return c.attentionAck(rest[2:])
		}
		return c.attention(rest[1:])
	case "api":
		return c.raw(rest[1:])
	default:
		fmt.Fprintf(stderr, "vmobs: unknown command %q\n\n", rest[0])
		usage(stderr)
		return exitUsage
	}
}

type client struct {
	base   string
	json   bool
	stdout io.Writer
	stderr io.Writer
}

func (c *client) do(method, path string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

// fail renders a non-2xx response. A body that is not a structured error is a
// protocol breakdown and reports as transport failure, not API failure.
func (c *client) fail(status int, body []byte) int {
	var e api.Error
	if err := json.Unmarshal(body, &e); err != nil || e.Code == "" {
		fmt.Fprintf(c.stderr, "vmobs: unstructured response (status %d): %s\n", status, body)
		return exitTransport
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitAPIError
	}
	fmt.Fprintf(c.stderr, "error: %s (cause %s): %s\n", e.Code, e.Cause, e.Message)
	for _, r := range e.Remediation {
		if len(r.Params) > 0 {
			fmt.Fprintf(c.stderr, "  try: %s %v — %s\n", r.Action, r.Params, r.Rationale)
		} else {
			fmt.Fprintf(c.stderr, "  try: %s — %s\n", r.Action, r.Rationale)
		}
	}
	return exitAPIError
}

func (c *client) transport(err error) int {
	fmt.Fprintf(c.stderr, "vmobs: cannot reach daemon at %s: %v\n", c.base, err)
	return exitTransport
}

func (c *client) meta() int {
	status, body, err := c.do(http.MethodGet, "/api/v1/meta", nil)
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
	var m struct {
		Service    string            `json:"service"`
		Version    string            `json:"version"`
		APIVersion string            `json:"api_version"`
		Features   map[string]bool   `json:"features"`
		Limits     map[string]int    `json:"limits"`
		Links      map[string]string `json:"links"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode manifest: %v\n", err)
		return exitTransport
	}
	fmt.Fprintf(c.stdout, "%s %s (api %s)\n", m.Service, m.Version, m.APIVersion)
	var built, unbuilt []string
	for f, on := range m.Features {
		if on {
			built = append(built, f)
		} else {
			unbuilt = append(unbuilt, f)
		}
	}
	sort.Strings(built)
	sort.Strings(unbuilt)
	fmt.Fprintf(c.stdout, "built:   %s\n", strings.Join(built, ", "))
	fmt.Fprintf(c.stdout, "unbuilt: %s\n", strings.Join(unbuilt, ", "))
	limitNames := make([]string, 0, len(m.Limits))
	for name := range m.Limits {
		limitNames = append(limitNames, name)
	}
	sort.Strings(limitNames)
	parts := make([]string, 0, len(limitNames))
	for _, name := range limitNames {
		parts = append(parts, fmt.Sprintf("%s=%d", name, m.Limits[name]))
	}
	fmt.Fprintf(c.stdout, "limits:  %s\n", strings.Join(parts, ", "))
	linkNames := make([]string, 0, len(m.Links))
	for name := range m.Links {
		linkNames = append(linkNames, name)
	}
	sort.Strings(linkNames)
	for _, name := range linkNames {
		fmt.Fprintf(c.stdout, "link:    %s %s\n", name, m.Links[name])
	}
	return exitOK
}

func (c *client) events(args []string) int {
	fs := flag.NewFlagSet("vmobs events", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	vm := fs.String("vm", "", "filter by vm id")
	kind := fs.String("kind", "", "filter by registered event kind")
	after := fs.String("after", "", "resume after this cursor (next_after of a previous page)")
	limit := fs.Int("limit", 0, "page size (default and max come from the daemon)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	params := url.Values{}
	if *vm != "" {
		params.Set("vm_id", *vm)
	}
	if *kind != "" {
		params.Set("kind", *kind)
	}
	if *after != "" {
		params.Set("after", *after)
	}
	if *limit != 0 {
		params.Set("limit", fmt.Sprint(*limit))
	}
	path := "/api/v1/events"
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
		Events        []*events.Envelope `json:"events"`
		NextAfter     string             `json:"next_after"`
		LatestEventID string             `json:"latest_event_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode events: %v\n", err)
		return exitTransport
	}
	for _, e := range resp.Events {
		id := "?"
		if e.EventID != nil {
			id = *e.EventID
		}
		scope := "host"
		if e.VMID != nil {
			scope = *e.VMID
		}
		fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\t%s\n",
			id, e.Kind, e.Provenance, scope,
			e.HostReceivedAt.UTC().Format("2006-01-02T15:04:05.000000Z"))
	}
	fmt.Fprintf(c.stdout, "next_after=%s latest_event_id=%s count=%d\n",
		resp.NextAfter, resp.LatestEventID, len(resp.Events))
	return exitOK
}

// raw is the escape hatch: any method, any path, body via -d, output verbatim.
func (c *client) raw(args []string) int {
	fs := flag.NewFlagSet("vmobs api", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	data := fs.String("d", "", "JSON request body")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(c.stderr, "usage: vmobs api [-d BODY] METHOD PATH")
		return exitUsage
	}
	method, path := strings.ToUpper(rest[0]), rest[1]
	if !strings.HasPrefix(path, "/") {
		fmt.Fprintf(c.stderr, "vmobs: path %q must start with /\n", path)
		return exitUsage
	}
	var body io.Reader
	if *data != "" {
		body = strings.NewReader(*data)
	}
	status, respBody, err := c.do(method, path, body)
	if err != nil {
		if strings.Contains(err.Error(), "invalid method") {
			fmt.Fprintf(c.stderr, "vmobs: %v\n", err)
			return exitUsage
		}
		return c.transport(err)
	}
	if status < 200 || status > 299 {
		return c.fail(status, respBody)
	}
	fmt.Fprintf(c.stdout, "%s\n", respBody)
	return exitOK
}
