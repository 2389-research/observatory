// ABOUTME: Serves observer rights over the existing authenticated privd endpoint.
// ABOUTME: Bounds lock wait and acquisition without persisting a false readiness claim.
//go:build linux

package privd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

func (s *Server) handleObserverConn(conn *net.UnixConn, req Request, raw json.RawMessage, framing time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), observerAcquisitionTimeout)
	defer cancel()
	bundle, err := s.acquireObservers(ctx, req, raw)
	response := Response{}
	if err != nil {
		response = backendErrResp(err)
	} else {
		defer bundle.Close()
		payload, marshalErr := json.Marshal(bundle)
		if marshalErr != nil {
			response = errResp("internal", "observer metadata serialization failed")
		} else {
			response = okResp(payload)
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(framing))
	var files = []*os.File(nil)
	if response.OK {
		files = bundle.Files
	}
	if err := writeMsgFiles(conn, response, files); err != nil {
		s.log.Printf("observer reply: %v", err)
	}
}
func (s *Server) acquireObservers(ctx context.Context, req Request, raw json.RawMessage) (*NetworkObserverBundle, error) {
	var envelope Request
	if err := decodeObserverJSON(raw, &envelope); err != nil || req.V != ProtoVersion || req.Verb != observerVerb || req.OpID != "" {
		return nil, &BackendError{Cause: "bad_request", Message: "invalid observer request envelope"}
	}
	var payload AcquireNetworkObserversReq
	if err := decodeObserverJSON(req.Payload, &payload); err != nil {
		return nil, &BackendError{Cause: "bad_request", Message: "invalid observer request payload"}
	}
	if err := validateObserverRequest(payload); err != nil {
		return nil, &BackendError{Cause: "bad_request", Message: err.Error()}
	}
	if err := s.lockObservers(ctx); err != nil {
		return nil, &BackendError{Cause: "unavailable", Message: "observer acquisition lock deadline exceeded"}
	}
	defer s.mu.Unlock()
	entry, err := s.ledger.get(payload.VMID)
	if errors.Is(err, os.ErrNotExist) {
		return nil, &BackendError{Cause: "not_found", Message: "network allocation not found"}
	}
	if err != nil {
		return nil, &BackendError{Cause: "invalid_state", Message: "network ownership cannot be read"}
	}
	if !entry.NetworkComplete || entry.NetworkGuestBootID != payload.GuestBootID {
		return nil, &BackendError{Cause: "invalid_state", Message: "network allocation is incomplete or bound to another guest boot"}
	}
	backend, ok := s.cfg.Ops.(interface {
		AcquireNetworkObservers(context.Context, VMEntry, AcquireNetworkObserversReq) (*NetworkObserverBundle, error)
	})
	if !ok {
		return nil, &BackendError{Cause: "unsupported", Message: "network observer backend unavailable"}
	}
	bundle, err := backend.AcquireNetworkObservers(ctx, entry, payload)
	if err != nil {
		if bundle != nil {
			_ = bundle.Close()
		}
		return nil, &BackendError{Cause: "unavailable", Message: truncateStderr([]byte(fmt.Sprintf("observer acquisition failed: %v", err)))}
	}
	return bundle, nil
}
func (s *Server) lockObservers(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.mu.TryLock() {
			if err := ctx.Err(); err != nil {
				s.mu.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
