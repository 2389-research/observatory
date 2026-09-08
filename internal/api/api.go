// ABOUTME: HTTP API server. One route table drives both the mux and the /meta
// ABOUTME: feature manifest, so self-description cannot drift from routing (P-07).
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
	"github.com/2389-research/observatory/internal/terminal"
)

// PreflightFunc is the preflight runner hook type. nil means no preflight
// block in /host/status — honest for tests and configs that don't wire it.
type PreflightFunc func(ctx context.Context, refresh bool) preflight.Report

const (
	Service    = "vmobsd"
	Version    = "0.1.0-dev"
	APIVersion = "v1"
	basePath   = "/api/v1"
)

// Server serves the /api/v1 surface over one store, one trigger engine, and
// the lifecycle manager. The manager is required; future refactors that make
// it optional should be explicit (not a nil-guard, which hides bugs).
type Server struct {
	store     *store.Store
	engine    *situation.Engine
	manager   *runtime.Manager
	mux       *http.ServeMux
	features  map[string]bool
	routes    []routeDescription
	links     map[string]string
	auth      authState
	preflight PreflightFunc // nil = no preflight block in /host/status

	// terminals is nil when this build serves no terminal registry; the four
	// terminal routes then answer 501 missing_capability, as they did before
	// one existed. termStreams places terminal events on their own source
	// streams, the way auth events have theirs — one per VM, because ingest
	// binds a source stream to exactly one VM scope.
	terminals   *terminal.Registry
	termMu      sync.Mutex
	termStreams map[string]*termStream
}

// termStream is one VM's terminal-event source stream: the instance id it
// emits under and the sequence that orders it.
type termStream struct {
	instanceID string
	seq        atomic.Int64
}

// terminalStream returns vmID's source stream, minting one on first use.
func (s *Server) terminalStream(vmID string) *termStream {
	s.termMu.Lock()
	defer s.termMu.Unlock()
	ts, ok := s.termStreams[vmID]
	if !ok {
		ts = &termStream{instanceID: uuid.NewString()}
		s.termStreams[vmID] = ts
	}
	return ts
}

type route struct {
	method  string // ignored for unbuilt routes: a stub answers every method
	pattern string
	feature string
	handler http.HandlerFunc // nil marks a specced-but-unbuilt route
}

// New wires the API over st, eng, mgr, the authentication config ac, an
// optional preflight hook pf, and an optional terminal registry tr. When pf is
// nil, /host/status omits the preflight block; when tr is nil, the terminal
// routes answer 501 — honest for tests and configs that don't wire them. Every
// endpoint in SPEC §14 is present in the table: built ones serve, unbuilt ones
// answer 501 missing_capability so an agent probing the spec surface is taught,
// not stonewalled.
func New(
	st *store.Store,
	eng *situation.Engine,
	mgr *runtime.Manager,
	ac AuthConfig,
	pf PreflightFunc,
	tr *terminal.Registry,
) http.Handler {
	s := &Server{
		store: st, engine: eng, manager: mgr, mux: http.NewServeMux(),
		auth: initAuthState(ac), preflight: pf,
		terminals: tr, termStreams: map[string]*termStream{},
	}
	table := []route{
		{"GET", "/meta", "meta", s.handleMeta},
		{"GET", "/meta/event-kinds", "meta", s.handleEventKinds},
		{"GET", "/telemetry/import", "telemetry_import", s.handleImportHealth},
		{"GET", "/vms/{id}/telemetry/import", "telemetry_import", s.handleImportHealth},
		{"GET", "/events", "events", s.handleEvents},
		{"GET", "/situation", "situation", s.handleSituation},
		{"GET", "/attention", "attention", s.handleAttention},
		{"POST", "/attention/{id}/ack", "attention", s.handleAttentionAck},
		{"POST", "/annotations", "annotations", s.handleAnnotationsCreate},
		{"GET", "/annotations", "annotations", s.handleAnnotationsList},
		{"GET", "/host/status", "host_status", s.handleHostStatus},
		{"GET", "/templates", "templates", s.handleTemplates},
		{"POST", "/vms", "vms", s.handleCreateVM},
		{"GET", "/vms", "vms", s.handleListVMs},
		{"GET", "/vms/{id}", "vms", s.handleGetVM},
		{"POST", "/vms/{id}/actions", "vms", s.handleVMAction},
		{"DELETE", "/vms/{id}", "vms", s.handleDeleteVM},
		{"GET", "/operations/{id}", "operations", s.handleGetOperation},

		{"POST", "/vm-batches", "vm_batches", s.handleCreateBatch},
		{"GET", "/vm-batches/{id}", "vm_batches", s.handleGetBatch},
		{"", "/events/stream", "events_stream", nil},
		{"", "/vms/{id}/execs", "execs", nil},
		{"", "/execs/{id}", "execs", nil},
		{"", "/execs/{id}/cancel", "execs", nil},
		{"", "/execs/{id}/output", "execs", nil},
		{"POST", "/vms/{id}/runs", "runs", s.handleCreateRunForVM},
		{"GET", "/runs", "runs", s.handleListRuns},
		{"GET", "/runs/{id}", "runs", s.handleGetRun},
		{"GET", "/runs/{id}/report", "runs", s.handleGetRunReport},
		{"POST", "/runs/{id}/conclude", "runs", s.handleConcludeRun},
		{"", "/vms/{id}/coverage", "coverage", nil},
		{"", "/vms/{id}/filesystem/diff", "filesystem_diff", nil},
		{"", "/vms/{id}/exports", "exports", nil},
		{"", "/artifacts/{id}", "artifacts", nil},
		// auth routes: login is exempt from the middleware; session is always readable.
		{"POST", "/auth/login", "auth", s.handleAuthLogin},
		{"POST", "/auth/logout", "auth", s.handleAuthLogout},
		{"GET", "/auth/session", "auth", s.handleAuthSession},
		{"POST", "/auth/tokens", "auth", s.handleTokenCreate},
		{"GET", "/auth/tokens", "auth", s.handleTokenList},
		{"DELETE", "/auth/tokens/{id}", "auth", s.handleTokenRevoke},
	}

	table = append(table, s.terminalRoutes()...)

	s.features = map[string]bool{}
	s.links = map[string]string{}
	allowed := map[string][]string{}
	for _, r := range table {
		s.routes = append(s.routes, describeRoute(r))
		if r.handler != nil && r.method == "GET" && !strings.Contains(r.pattern, "{") && (r.feature != "auth" || r.pattern == "/auth/session") {
			s.links[collectionLinkName(r)] = basePath + r.pattern
		}
		s.features[r.feature] = s.features[r.feature] || r.handler != nil
		if r.handler != nil {
			s.mux.Handle(r.method+" "+basePath+r.pattern, r.handler)
			allowed[r.pattern] = append(allowed[r.pattern], r.method)
		} else {
			s.mux.Handle(basePath+r.pattern, stub(r.feature))
		}
	}
	// A built path hit with the wrong method falls through to this twin.
	for pattern, methods := range allowed {
		s.mux.Handle(basePath+pattern, methodNotAllowed(methods))
	}
	mountUI(s.mux)
	s.mux.Handle("/", http.HandlerFunc(notFound))
	return s.withAuth(s.mux)
}

// terminalRoutes is one row per terminal pattern, built or stubbed as a unit.
// A pattern registered twice panics the mux, so the two shapes are alternatives
// rather than a table that adds rows when the registry is present.
func (s *Server) terminalRoutes() []route {
	if s.terminals == nil {
		return []route{
			{"", "/vms/{id}/terminals", "terminals", nil},
			{"", "/terminals/{id}", "terminals", nil},
			{"", "/terminals/{id}/lease", "terminals", nil},
			{"", "/terminals/{id}/stream", "terminals", nil},
		}
	}
	return []route{
		{"POST", "/vms/{id}/terminals", "terminals", s.handleCreateTerminal},
		{"GET", "/vms/{id}/terminals", "terminals", s.handleListTerminals},
		{"DELETE", "/terminals/{id}", "terminals", s.handleCloseTerminal},
		{"POST", "/terminals/{id}/lease", "terminals", s.handleTerminalLease},
		{"GET", "/terminals/{id}/stream", "terminals", s.handleTerminalStream},
	}
}

func stub(feature string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotImplemented, Error{
			Code:        "missing_capability",
			Message:     fmt.Sprintf("the %s capability is specified but not built in this version", feature),
			Retryable:   false,
			Cause:       "capability_not_built",
			Details:     map[string]any{"feature": feature},
			Remediation: []Remediation{metaRemediation()},
		})
	}
}

func methodNotAllowed(methods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, m := range methods {
			w.Header().Add("Allow", m)
		}
		writeError(w, http.StatusMethodNotAllowed, Error{
			Code:      "method_not_allowed",
			Message:   fmt.Sprintf("%s is not served on this path", r.Method),
			Retryable: false,
			Cause:     "method_mismatch",
			Details:   map[string]any{"allowed": methods},
		})
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, Error{
		Code:        "not_found",
		Message:     fmt.Sprintf("no route for %s", r.URL.Path),
		Retryable:   false,
		Cause:       "route_unknown",
		Remediation: []Remediation{metaRemediation()},
	})
}

type limits struct {
	EventsPageDefault         int   `json:"events_page_default"`
	EventsPageMax             int   `json:"events_page_max"`
	AnnotationTextMaxBytes    int   `json:"annotation_text_max_bytes"`
	AttentionQueueMaxItems    int   `json:"attention_queue_max_items"`
	SituationMaxResponseBytes int64 `json:"situation_max_response_bytes"`
	MaxBatchSize              int   `json:"max_batch_size"`
}

type metaAuth struct {
	Required bool   `json:"required"`
	Mode     string `json:"mode"`
}

type meta struct {
	Routes                  []routeDescription `json:"routes"`
	Agent                   map[string]any     `json:"agent"`
	Service                 string             `json:"service"`
	Version                 string             `json:"version"`
	APIVersion              string             `json:"api_version"`
	Features                map[string]bool    `json:"features"`
	Limits                  limits             `json:"limits"`
	AttentionTriggerClasses []string           `json:"attention_trigger_classes"`
	Links                   map[string]string  `json:"links"`
	Auth                    metaAuth           `json:"auth"`
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, meta{
		Service:    Service,
		Version:    Version,
		APIVersion: APIVersion,
		Features:   s.features,
		Limits: limits{
			EventsPageDefault:         store.DefaultPageLimit,
			EventsPageMax:             store.MaxPageLimit,
			AnnotationTextMaxBytes:    store.AnnotationTextMaxBytes,
			AttentionQueueMaxItems:    s.engine.Config().QueueMaxItems,
			SituationMaxResponseBytes: s.engine.Config().SituationMaxResponseBytes,
			MaxBatchSize:              s.maxBatchSize(),
		},
		// The active set is enabled-intersect-implemented, straight from the
		// engine: config alone must not claim a watch no code performs (P-03).
		AttentionTriggerClasses: s.engine.ActiveClasses(),
		Links:                   s.links,
		Routes:                  s.routes,
		Agent:                   agentContract(),
		Auth: metaAuth{
			Required: s.auth.ac.Enabled,
			Mode:     "local_operator",
		},
	})
}

func (s *Server) handleEventKinds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"kinds": events.Kinds()})
}
