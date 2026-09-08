// ABOUTME: Describes the bounded agent workflow using the server's route table.
// ABOUTME: Examples share request types with handlers; deferred controls stay explicit.
package api

import (
	"strings"
)

// routeDescription exposes templates as templates, never as GET links. An
// omitted example means the catalog describes routing only for that endpoint.
type routeDescription struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	Feature        string `json:"feature"`
	Built          bool   `json:"built"`
	Purpose        string `json:"purpose,omitempty"`
	RequestExample any    `json:"request_example,omitempty"`
	Instructions   string `json:"instructions,omitempty"`
}

func describeRoute(r route) routeDescription {
	d := routeDescription{Method: r.method, Path: basePath + r.pattern, Feature: r.feature, Built: r.handler != nil}
	if !d.Built {
		return d
	}
	switch r.method + " " + r.pattern {
	case "GET /meta":
		d.Purpose = "describe"
	case "GET /situation":
		d.Purpose = "snapshot"
		d.Instructions = "Optional since is a previously saved as_of_cursor. This is a live projection, not an atomic historical snapshot. Expand omitted sections before concluding there is no work."
	case "GET /templates":
		d.Purpose = "templates"
	case "GET /host/status":
		d.Purpose = "capacity"
	case "GET /events":
		d.Purpose = "events"
		d.Instructions = "Use after=<saved cursor>&limit=<events_page_max or smaller>. Process all events, then persist next_after. An empty page preserves after. Do not advance to latest_event_id: a bounded page may omit intervening events. Optional until freezes the event upper bound. Optional vm_id and boot_id scope observation identity; kind and family are mutually exclusive. Preserve filters when resuming."
	case "GET /events/stream":
		d.Purpose = "live_events"
		d.Instructions = "SSE messages carry one event envelope and its durable event_id as id. Resume with Last-Event-ID, which overrides after, and preserve vm_id, boot_id and kind or family filters. Limit is at most 32 per query; tail applies only to the initial page; until is not supported. Idle comments do not advance the cursor. stream_error terminates the connection. This is authenticated shared host observation, not an owner-private feed. Cursors require the same database installation; retention-gap detection is unavailable."
	case "GET /vms/{id}/coverage":
		d.Purpose = "capture_coverage"
		d.Instructions = "Read boot_id before querying a VM's current observations. Channel health describes guest transport; each collector reports its own scope, limitations and loss. Null counts mean unknown, not zero. A healthy collector does not promise complete capture."
	case "POST /vms":
		d.Purpose = "launch"
		key := "$idempotency_key"
		run := &runBlockBody{Goal: "$goal", OnCompletion: "keep_running"}
		run.SuccessCriteria.Type = "operator_verdict"
		d.RequestExample = createVMBody{Name: "$name", TemplateID: "$template_id", IdempotencyKey: &key, Run: run}
		d.Instructions = "Replace $name with a unique VM name, $template_id with a templates response template_id, $idempotency_key with a fresh unique nonempty string, and $goal with your goal. Zero resource values use host defaults. Save the exact request before sending. A lost response may be retried with the same key and identical body; never change the payload under that key. Returns vm and operation; follow their links. Owner comes from authentication."
	case "POST /vms/{id}/actions":
		d.Purpose = "action"
		d.RequestExample = vmActionBody{Action: "stop", ExpectedRevision: "$revision"}
		d.Instructions = "Replace {id} with vm_id and $revision with the revision from a fresh VM read. Example stops a VM; start and stop are supported. A revision mismatch requires refreshing and reassessing intent; it is not permission to retry blindly. After a lost response inspect the VM and operation before any new action."
	case "POST /runs/{id}/conclude":
		d.Purpose = "conclude"
		verdict := "succeeded"
		d.RequestExample = concludeRunBody{Verdict: &verdict, Reason: "$reason"}
		d.Instructions = "Replace {id} with run_id and $reason with your evidence-based assessment. This example asserts an operator verdict, not a guest result; use failed for failure. Abort uses abort:true without verdict. Read run.outcome and its report afterwards."
	}
	return d
}

// collectionLinkName preserves the public collection link names while deriving
// targets from the registered GET routes. Mutations and templates use routes.
func collectionLinkName(r route) string {
	name := strings.TrimPrefix(r.pattern, "/")
	name = strings.TrimPrefix(name, "meta/")
	return strings.NewReplacer("/", "_", "-", "_").Replace(name)
}

func agentContract() map[string]any {
	return map[string]any{
		"workflow":   []string{"describe", "capacity", "templates", "snapshot", "launch", "poll operation.links.self", "read vm.links.runs", "conclude", "read run.links.self and run.links.report", "refresh vm.links.self", "action", "resume"},
		"resume":     "Before launch, persist snapshot.as_of_cursor and the exact keyed request. Persist returned VM/operation/run links. After reconnect, query saved operation.links.self; if the launch response was lost, resend the exact keyed launch. Resume events using after=saved cursor and bounded limit, persisting only next_after after processing the whole page. Situation since is orientation, not an event-consumption checkpoint. Same database installation required; restoring/replacing the database invalidates saved anchors. There is no server checkpoint API or event-retention gap detector.",
		"recovery":   map[string]string{"never": "Do not automatically retry; inspect the error and remedy the request or unsupported capability.", "same_request": "For a safe read, retry the same request; for launch only, retain the exact body and idempotency key.", "query_operation": "Read the operation link first; an effect may already have occurred. Do not recreate the mutation to learn its status.", "after_refresh": "Read current state/cursors and reassess before choosing another action.", "after_precondition": "Satisfy the stated precondition before a new attempt; this does not promise a mutation is replay-safe."},
		"plan_apply": false, "exact_plan_approval": false, "work_budgets": false, "server_checkpoints": false, "mutation_watch_cursor": false,
		"scope": "VM, operation and run reads/mutations are owner scoped. Situation and events describe shared host observation; they are not owner-private views. Host reservations enforce admission capacity, not per-work budgets.",
	}
}
