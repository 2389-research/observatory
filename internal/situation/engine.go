// ABOUTME: Deterministic trigger engine and situation snapshot (SPEC §12.7):
// ABOUTME: a lazy, crash-safe cursor fold over the event stream raises attention.
package situation

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

// CursorName is the durable engine cursor: everything at or before it has been
// evaluated exactly once.
const CursorName = "attention_triggers"

// Config carries the agent_interface host configuration the engine obeys.
// Triggers maps class -> enabled; only implemented classes ever raise.
// SituationMaxResponseBytes is enforced by the API when rendering; it lives
// here so agent_interface config has one home.
type Config struct {
	Triggers                  map[string]bool
	QueueMaxItems             int
	CollapseDuplicates        bool
	SituationMaxResponseBytes int64
}

// Engine evaluates registered trigger rules over the durable stream. It holds
// no state of its own: the cursor and the queue live in the store, so a fresh
// process resumes exactly where the last one stopped.
type Engine struct {
	st  *store.Store
	cfg Config
}

func New(st *store.Store, cfg Config) *Engine {
	return &Engine{st: st, cfg: cfg}
}

// Config returns the engine's configuration so serving layers report the
// limits actually in force rather than restating config themselves.
func (e *Engine) Config() Config { return e.cfg }

// rule maps one event kind to the attention it deserves. Summaries state what
// happened; system actions state what the system already did — both from the
// record, never speculation.
// match is an optional predicate: nil means "match all events of this kind".
// severity is used when fixed; severityFn overrides it for event-dependent grades.
// evidenceFn and actionsFn override the per-event evidence links and suggested
// actions when the default (event cursor link) is insufficient.
type rule struct {
	class        string
	severity     string
	severityFn   func(env *events.Envelope) string // overrides severity when non-nil
	match        func(env *events.Envelope) bool
	summary      func(env *events.Envelope) string
	systemAction string
	evidenceFn   func(env *events.Envelope, id int64) []string      // overrides default evidence links
	actionsFn    func(env *events.Envelope) []store.SuggestedAction // extra suggested actions
}

// reconciliationReasons are the reasons the controller uses when cleaning up
// state after a restart. They distinguish expected reconciliation from genuine
// unexpected failures so both can fire distinct trigger classes.
var reconciliationReasons = map[string]bool{
	"controller_restart":         true,
	"vmm_disappeared_on_restart": true,
}

// terminalRunPhases is the set of run phases from which no further transitions
// exist. Mirrors the same constant in the store package without importing it.
var terminalRunPhases = map[string]bool{
	"succeeded":    true,
	"failed":       true,
	"inconclusive": true,
	"aborted":      true,
}

// envVMID returns the VM ID from the envelope if set, otherwise from event data.
// Host-observed lifecycle events carry vm_id in data, not at the envelope level.
func envVMID(env *events.Envelope) *string {
	if env.VMID != nil {
		return env.VMID
	}
	if s, ok := env.Data["vm_id"].(string); ok && s != "" {
		return &s
	}
	return nil
}

// runIDFromData extracts run_id from event data, or returns nil. Used for
// run.state_changed events where run linkage lives in data, not the envelope.
func runIDFromData(env *events.Envelope) *string {
	if s, ok := env.Data["run_id"].(string); ok && s != "" {
		return &s
	}
	return nil
}

// rulesByKind is the implemented trigger set. A kind may have multiple rules
// when data content determines which class fires. Classes configured but absent
// here are not watched, and ActiveClasses will not claim they are.
var rulesByKind = map[string][]rule{
	"telemetry.loss": {{
		class:    "telemetry_degraded",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			return fmt.Sprintf("telemetry loss reported by sensor %q; counts are in the event record", env.Sensor)
		},
		systemAction: "recorded the loss as evidence; capture continues",
	}},
	"telemetry.integrity_failure": {{
		class:    "telemetry_degraded",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			failure, _ := env.Data["failure"].(string)
			if failure == "" {
				failure = "unspecified"
			}
			return fmt.Sprintf("telemetry stream integrity failure (%s)", failure)
		},
		systemAction: "rejected the conflicting append; the original event stands",
	}},
	"telemetry.unregistered_kind": {{
		class:    "telemetry_degraded",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			kind, _ := env.Data["kind"].(string)
			return fmt.Sprintf("producer sent unregistered event kind %q", kind)
		},
		systemAction: "rejected the append; kinds must be registered before ingest",
	}},

	// vm.state_changed fires two distinct classes depending on data.reason.
	"vm.state_changed": {
		{
			class:    "lifecycle_failed",
			severity: store.SeverityNeedsDecision,
			match: func(env *events.Envelope) bool {
				to, _ := env.Data["to"].(string)
				reason, _ := env.Data["reason"].(string)
				return to == "failed" && !reconciliationReasons[reason]
			},
			summary: func(env *events.Envelope) string {
				vmID, _ := env.Data["vm_id"].(string)
				from, _ := env.Data["from"].(string)
				reason, _ := env.Data["reason"].(string)
				return fmt.Sprintf("VM %s failed from %s: %s", vmID, from, reason)
			},
			systemAction: "recorded the failure; VM compute released, history preserved",
		},
		{
			class:    "reconciliation_surprise",
			severity: store.SeverityNeedsDecision,
			match: func(env *events.Envelope) bool {
				reason, _ := env.Data["reason"].(string)
				return reconciliationReasons[reason]
			},
			summary: func(env *events.Envelope) string {
				vmID, _ := env.Data["vm_id"].(string)
				reason, _ := env.Data["reason"].(string)
				return fmt.Sprintf("VM %s found in unexpected state on restart: %s", vmID, reason)
			},
			systemAction: "recorded the unexpected state; VM compute released, history preserved",
		},
	},

	// vm.cleanup_failed is a lifecycle operation that did not complete: the
	// operator asked for a stop or a delete and the host still owns the
	// resources. It fires lifecycle_failed rather than reconciliation_surprise
	// because it is raised on both paths -- the synchronous DELETE and the
	// restart retry -- and only one of those is a restart.
	"vm.cleanup_failed": {{
		class:    "lifecycle_failed",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			vmID, _ := env.Data["vm_id"].(string)
			state, _ := env.Data["state"].(string)
			reason, _ := env.Data["reason"].(string)
			return fmt.Sprintf("cleanup of VM %s did not complete; the row is held at %s: %s", vmID, state, reason)
		},
		systemAction: "retained the row and its resource reservations; the cleanup is retried at every controller start",
		actionsFn: func(env *events.Envelope) []store.SuggestedAction {
			vmID, _ := env.Data["vm_id"].(string)
			if vmID == "" {
				return nil
			}
			return []store.SuggestedAction{
				{
					Action:    "delete",
					Params:    map[string]any{"path": "/api/v1/vms/" + vmID + "?force=true"},
					Rationale: "retry the cleanup once the cause named in the summary is cleared on the host",
				},
			}
		},
	}},

	// vm.reconcile_ambiguous is the startup scan declining to guess. It fires
	// reconciliation_surprise for the same reason "vmm_disappeared_on_restart"
	// does -- it can only be raised by a restart -- and it is the more urgent of
	// the two: that one describes a row the controller settled, this one a row
	// nobody could settle, still holding its reservations.
	"vm.reconcile_ambiguous": {{
		class:    "reconciliation_surprise",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			vmID, _ := env.Data["vm_id"].(string)
			state, _ := env.Data["state"].(string)
			detail, _ := env.Data["detail"].(string)
			return fmt.Sprintf("VM %s could not be classified on restart; the row is held at %s: %s", vmID, state, detail)
		},
		systemAction: "left the row and its resource reservations exactly as the last controller wrote them",
		actionsFn: func(env *events.Envelope) []store.SuggestedAction {
			vmID, _ := env.Data["vm_id"].(string)
			if vmID == "" {
				return nil
			}
			return []store.SuggestedAction{
				{
					Action:    "get",
					Params:    map[string]any{"path": "/api/v1/events?vm_id=" + vmID},
					Rationale: "the row is the last controller's word; this VM's event history is what led to it",
				},
			}
		},
	}},

	// run.state_changed fires only on terminal transitions. The event is
	// store-synthesized: vm_id is in data, not the envelope. succeeded → info;
	// failed/inconclusive/aborted → needs_decision (operator must review report).
	"run.state_changed": {{
		class: "run_concluded",
		match: func(env *events.Envelope) bool {
			to, _ := env.Data["to"].(string)
			return terminalRunPhases[to]
		},
		severityFn: func(env *events.Envelope) string {
			to, _ := env.Data["to"].(string)
			if to == "succeeded" {
				return store.SeverityInfo
			}
			return store.SeverityNeedsDecision
		},
		summary: func(env *events.Envelope) string {
			vmID, _ := env.Data["vm_id"].(string)
			runID, _ := env.Data["run_id"].(string)
			to, _ := env.Data["to"].(string)
			evaluatedBy, _ := env.Data["evaluated_by"].(string)
			reason, _ := env.Data["reason"].(string)
			s := fmt.Sprintf("run %s on VM %s concluded %s", runID, vmID, to)
			if evaluatedBy != "" {
				s += fmt.Sprintf("; evaluated_by %s", evaluatedBy)
			}
			if reason != "" {
				s += fmt.Sprintf(": %s", reason)
			}
			return s
		},
		systemAction: "recorded the terminal phase; report generation enqueued",
		evidenceFn: func(env *events.Envelope, _ int64) []string {
			runID, _ := env.Data["run_id"].(string)
			if runID == "" {
				return []string{}
			}
			return []string{
				"/api/v1/runs/" + runID,
				"/api/v1/runs/" + runID + "/report",
			}
		},
		actionsFn: func(env *events.Envelope) []store.SuggestedAction {
			runID, _ := env.Data["run_id"].(string)
			if runID == "" {
				return nil
			}
			return []store.SuggestedAction{
				{
					Action:    "get",
					Params:    map[string]any{"path": "/api/v1/runs/" + runID + "/report"},
					Rationale: "review the run report to understand the outcome",
				},
			}
		},
	}},

	// operation.state_changed fires when a create is refused due to capacity.
	"operation.state_changed": {{
		class:    "capacity_exhausted",
		severity: store.SeverityNeedsDecision,
		match: func(env *events.Envelope) bool {
			state, _ := env.Data["state"].(string)
			if state != "failed" {
				return false
			}
			errData, _ := env.Data["error"].(map[string]any)
			cause, _ := errData["cause"].(string)
			return cause == "insufficient_capacity"
		},
		summary: func(env *events.Envelope) string {
			errData, _ := env.Data["error"].(map[string]any)
			msg, _ := errData["message"].(string)
			return fmt.Sprintf("create rejected: capacity exhausted — %s", msg)
		},
		systemAction: "rejected the create; no VM or reservation was written",
	}},
}

// ActiveClasses is the honest watch scope: configured-enabled AND implemented.
// Serving a configured-only set would present blind calm as monitored calm (P-03).
func (e *Engine) ActiveClasses() []string {
	implemented := map[string]bool{}
	for _, rules := range rulesByKind {
		for _, r := range rules {
			implemented[r.class] = true
		}
	}
	var active []string
	for class, enabled := range e.cfg.Triggers {
		if enabled && implemented[class] {
			active = append(active, class)
		}
	}
	sort.Strings(active)
	if active == nil {
		active = []string{}
	}
	return active
}

// Evaluate folds trigger rules over events past the durable cursor. Each raise
// advances the cursor in the same transaction, so a crash between raises never
// re-raises; spans without matches advance in one step per page. Raised
// attention events land after the cursor and are scanned on the next pass,
// where they match no rule — the fold always terminates.
func (e *Engine) Evaluate(ctx context.Context) error {
	cursor, err := e.st.ReadEngineCursor(ctx, CursorName)
	if err != nil {
		return err
	}
	for {
		page, err := e.st.Query(ctx, store.Query{
			After: strconv.FormatInt(cursor, 10),
			Limit: store.MaxPageLimit,
		})
		if err != nil {
			return err
		}
		if len(page.Events) == 0 {
			return nil
		}
		for _, env := range page.Events {
			id, err := strconv.ParseInt(*env.EventID, 10, 64)
			if err != nil {
				return fmt.Errorf("stored cursor %q does not parse: %w", *env.EventID, err)
			}
			cursor = id
			rules, ok := rulesByKind[env.Kind]
			if !ok {
				continue
			}
			for _, r := range rules {
				if !e.cfg.Triggers[r.class] {
					continue
				}
				if r.match != nil && !r.match(env) {
					continue
				}
				severity := r.severity
				if r.severityFn != nil {
					severity = r.severityFn(env)
				}
				evidenceLinks := []string{
					fmt.Sprintf("/api/v1/events?after=%d&limit=1", id-1),
				}
				if r.evidenceFn != nil {
					evidenceLinks = r.evidenceFn(env, id)
				}
				var suggestedActions []store.SuggestedAction
				if r.actionsFn != nil {
					suggestedActions = r.actionsFn(env)
				}
				// run.state_changed carries vm_id and run_id in data.
				runID := runIDFromData(env)
				if _, err := e.st.RaiseAttention(ctx, store.RaiseInput{
					TriggerClass:     r.class,
					Severity:         severity,
					VMID:             envVMID(env),
					RunID:            runID,
					Summary:          r.summary(env),
					SystemAction:     r.systemAction,
					EvidenceLinks:    evidenceLinks,
					SuggestedActions: suggestedActions,
					Collapse:         e.cfg.CollapseDuplicates,
					QueueMax:         e.cfg.QueueMaxItems,
					CursorName:       CursorName,
					CursorTo:         id,
				}); err != nil {
					return fmt.Errorf("raise for event %d: %w", id, err)
				}
			}
		}
		// Cover the trailing non-matching span; a no-op overwrite when the
		// last event of the page raised (cursor already there).
		if err := e.st.AdvanceEngineCursor(ctx, CursorName, cursor); err != nil {
			return err
		}
	}
}

// Snapshot is the situation summary: deterministic materialization of durable
// records (P-08). VMsRunning and VMsTotal stay zero here — the API counts them
// straight from the registry for its own response, and a second count in this
// struct would be a second source of truth for the same fact.
type Snapshot struct {
	AsOfCursor      string
	SinceCursor     string
	Quiet           bool
	VMsRunning      int
	VMsTotal        int
	ActiveClasses   []string
	SensorsDegraded int
	AttentionOpen   int64
	Head            []*store.AttentionItem
}

// headLimit bounds the attention head in the snapshot; the full queue lives
// behind GET /attention.
const headLimit = 10

// Snapshot reports the current situation. since="" is the full snapshot;
// otherwise only novelty past that cursor decides quiet. Quiet means: nothing
// new since, and nothing open awaiting a decision.
func (e *Engine) Snapshot(ctx context.Context, since string) (*Snapshot, error) {
	sinceID := int64(-1)
	if since != "" {
		if !events.DecimalString(since) {
			return nil, fmt.Errorf("since %q: %w", since, store.ErrInvalidCursor)
		}
		v, err := strconv.ParseInt(since, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("since %q: %w", since, store.ErrInvalidCursor)
		}
		sinceID = v
	}

	// Limit 1 is the cheapest honest way to learn the latest cursor.
	probe, err := e.st.Query(ctx, store.Query{Limit: 1})
	if err != nil {
		return nil, err
	}
	latest := int64(0)
	if probe.LatestEventID != "" {
		if latest, err = strconv.ParseInt(probe.LatestEventID, 10, 64); err != nil {
			return nil, fmt.Errorf("latest cursor %q does not parse: %w", probe.LatestEventID, err)
		}
	}

	open, err := e.st.CountOpenAttention(ctx)
	if err != nil {
		return nil, err
	}
	head, err := e.st.OpenAttentionHead(ctx, headLimit)
	if err != nil {
		return nil, err
	}
	degraded, err := e.sensorsDegraded(ctx)
	if err != nil {
		return nil, err
	}

	snap := &Snapshot{
		AsOfCursor:      strconv.FormatInt(latest, 10),
		SinceCursor:     since,
		Quiet:           open == 0 && (sinceID < 0 || latest <= sinceID),
		ActiveClasses:   e.ActiveClasses(),
		SensorsDegraded: degraded,
		AttentionOpen:   open,
		Head:            head,
	}
	return snap, nil
}
