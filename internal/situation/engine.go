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
type Config struct {
	Triggers           map[string]bool
	QueueMaxItems      int
	CollapseDuplicates bool
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

// rule maps one event kind to the attention it deserves. Summaries state what
// happened; system actions state what the system already did — both from the
// record, never speculation.
type rule struct {
	class        string
	severity     string
	summary      func(env *events.Envelope) string
	systemAction string
}

// rulesByKind is the implemented trigger set. Classes configured but absent
// here are not watched, and ActiveClasses will not claim they are.
var rulesByKind = map[string]rule{
	"telemetry.loss": {
		class:    "telemetry_degraded",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			return fmt.Sprintf("telemetry loss reported by sensor %q; counts are in the event record", env.Sensor)
		},
		systemAction: "recorded the loss as evidence; capture continues",
	},
	"telemetry.integrity_failure": {
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
	},
	"telemetry.unregistered_kind": {
		class:    "telemetry_degraded",
		severity: store.SeverityNeedsDecision,
		summary: func(env *events.Envelope) string {
			kind, _ := env.Data["kind"].(string)
			return fmt.Sprintf("producer sent unregistered event kind %q", kind)
		},
		systemAction: "rejected the append; kinds must be registered before ingest",
	},
}

// ActiveClasses is the honest watch scope: configured-enabled AND implemented.
// Serving a configured-only set would present blind calm as monitored calm (P-03).
func (e *Engine) ActiveClasses() []string {
	implemented := map[string]bool{}
	for _, r := range rulesByKind {
		implemented[r.class] = true
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
			r, ok := rulesByKind[env.Kind]
			if !ok || !e.cfg.Triggers[r.class] {
				continue
			}
			if _, err := e.st.RaiseAttention(ctx, store.RaiseInput{
				TriggerClass: r.class,
				Severity:     r.severity,
				VMID:         env.VMID,
				Summary:      r.summary(env),
				SystemAction: r.systemAction,
				EvidenceLinks: []string{
					fmt.Sprintf("/api/v1/events?after=%d&limit=1", id-1),
				},
				Collapse:   e.cfg.CollapseDuplicates,
				QueueMax:   e.cfg.QueueMaxItems,
				CursorName: CursorName,
				CursorTo:   id,
			}); err != nil {
				return fmt.Errorf("raise for event %d: %w", id, err)
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
// records (P-08). VM roll-ups stay zero until the VM manager exists — served
// as zeros because that is the truth of this host today, not a placeholder.
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

	snap := &Snapshot{
		AsOfCursor:    strconv.FormatInt(latest, 10),
		SinceCursor:   since,
		Quiet:         open == 0 && (sinceID < 0 || latest <= sinceID),
		ActiveClasses: e.ActiveClasses(),
		AttentionOpen: open,
		Head:          head,
	}
	return snap, nil
}
