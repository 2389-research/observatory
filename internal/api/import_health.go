// ABOUTME: Serves bounded host and owner-scoped VM spool import diagnostics.
// ABOUTME: Reads the same live status used by telemetry health and attention links.
package api

import "net/http"

func (s *Server) handleImportHealth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id != "" {
		vm, err := s.store.GetVM(r.Context(), id)
		if err != nil {
			writeVMError(w, err)
			return
		}
		if !s.resourceOwner(w, r, vm.Owner) {
			return
		}
	}
	writeJSON(w, http.StatusOK, s.engine.ImporterStatus(id))
}
