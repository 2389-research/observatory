// ABOUTME: HTTP API server. One route table drives both the mux and the /meta
// ABOUTME: feature manifest, so self-description cannot drift from routing (P-07).
package api

import (
	"fmt"
	"net/http"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

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
	store    *store.Store
	engine   *situation.Engine
	manager  *runtime.Manager
	mux      *http.ServeMux
	features map[string]bool
}

type route struct {
	method  string // ignored for unbuilt routes: a stub answers every method
	pattern string
	feature string
	handler http.HandlerFunc // nil marks a specced-but-unbuilt route
}

// New wires the API over st, eng, and mgr. Every endpoint in SPEC §14 is
// present in the table: built ones serve, unbuilt ones answer 501
// missing_capability so an agent probing the spec surface is taught, not
// stonewalled.
func New(st *store.Store, eng *situation.Engine, mgr *runtime.Manager) http.Handler {
	s := &Server{store: st, engine: eng, manager: mgr, mux: http.NewServeMux()}
	table := []route{
		{"GET", "/meta", "meta", s.handleMeta},
		{"GET", "/meta/event-kinds", "meta", s.handleEventKinds},
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
		{"", "/vms/{id}/terminals", "terminals", nil},
		{"", "/terminals/{id}", "terminals", nil},
		{"", "/terminals/{id}/stream", "terminals", nil},
		{"", "/terminals/{id}/lease", "terminals", nil},
		{"", "/vms/{id}/execs", "execs", nil},
		{"", "/execs/{id}", "execs", nil},
		{"", "/execs/{id}/cancel", "execs", nil},
		{"", "/execs/{id}/output", "execs", nil},
		{"", "/vms/{id}/runs", "runs", nil},
		{"", "/runs", "runs", nil},
		{"", "/runs/{id}", "runs", nil},
		{"", "/runs/{id}/report", "runs", nil},
		{"", "/runs/{id}/conclude", "runs", nil},
		{"", "/vms/{id}/coverage", "coverage", nil},
		{"", "/vms/{id}/filesystem/diff", "filesystem_diff", nil},
		{"", "/vms/{id}/exports", "exports", nil},
		{"", "/artifacts/{id}", "artifacts", nil},
	}

	s.features = map[string]bool{}
	allowed := map[string][]string{}
	for _, r := range table {
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
	s.mux.Handle("/", http.HandlerFunc(notFound))
	return s.mux
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

type meta struct {
	Service                 string            `json:"service"`
	Version                 string            `json:"version"`
	APIVersion              string            `json:"api_version"`
	Features                map[string]bool   `json:"features"`
	Limits                  limits            `json:"limits"`
	AttentionTriggerClasses []string          `json:"attention_trigger_classes"`
	Links                   map[string]string `json:"links"`
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
			MaxBatchSize:              MaxBatchSize,
		},
		// The active set is enabled-intersect-implemented, straight from the
		// engine: config alone must not claim a watch no code performs (P-03).
		AttentionTriggerClasses: s.engine.ActiveClasses(),
		// Links name only what answers 200 today. The guide and OpenAPI join
		// this map when they exist, not before.
		Links: map[string]string{
			"event_kinds": basePath + "/meta/event-kinds",
			"events":      basePath + "/events",
			"situation":   basePath + "/situation",
			"attention":   basePath + "/attention",
			"annotations": basePath + "/annotations",
			"host_status": basePath + "/host/status",
			"templates":   basePath + "/templates",
			"vms":         basePath + "/vms",
		},
	})
}

func (s *Server) handleEventKinds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"kinds": events.Kinds()})
}
