// ABOUTME: Serves current VM/boot collector coverage from the situation engine.
// ABOUTME: Checks ownership before reading capture health or exposing its scope.
package api

import "net/http"

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	vm, err := s.store.GetVM(r.Context(), r.PathValue("id"))
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, vm.Owner) {
		return
	}
	coverage, err := s.engine.VMCoverage(r.Context(), vm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "coverage query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}
	writeJSON(w, http.StatusOK, coverage)
}
