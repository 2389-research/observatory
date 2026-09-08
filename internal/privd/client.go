// ABOUTME: Dial-per-call privd client: one unix-socket connection per request.
// ABOUTME: Each call dials, writes the request, reads the response, and closes.
package privd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net"
)

// Client is a privd client. SocketPath is the path to the privd unix socket.
// All methods dial fresh for each call (one request per connection).
type Client struct {
	SocketPath string
}

type operationIDKey struct{}

// WithOperationID binds a retry to the exact original mutation request.
func WithOperationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, operationIDKey{}, id)
}

// UnknownOutcomeError preserves the mutation identity when transport loses its reply.
type UnknownOutcomeError struct {
	OpID string
	Err  error
}

func (e *UnknownOutcomeError) Error() string {
	return fmt.Sprintf("privd operation %s outcome unknown: %v", e.OpID, e.Err)
}
func (e *UnknownOutcomeError) Unwrap() error { return e.Err }

// QueryOperation returns a durable outcome without waiting for the host execution lock.
func (c *Client) QueryOperation(ctx context.Context, id string) (OperationOutcome, error) {
	var out OperationOutcome
	err := c.call(ctx, "query_operation", "", struct {
		OpID string `json:"op_id"`
	}{id}, &out)
	return out, err
}

// call is the shared request/response helper for all verb methods.
func (c *Client) call(ctx context.Context, verb, opID string, payload, out any) error {
	mutation := verb != "query_operation" && verb != "network_leases"
	if mutation && opID == "" {
		opID, _ = ctx.Value(operationIDKey{}).(string)
		if opID == "" {
			opID = uuid.NewString()
		}
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("dial privd %s: %w", c.SocketPath, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", verb, err)
	}
	if err := WriteMsg(conn, Request{V: ProtoVersion, Verb: verb, OpID: opID, Payload: raw}); err != nil {
		if mutation {
			return &UnknownOutcomeError{OpID: opID, Err: err}
		}
		return fmt.Errorf("send %s: %w", verb, err)
	}
	var resp Response
	if err := ReadMsg(conn, &resp); err != nil {
		if mutation {
			return &UnknownOutcomeError{OpID: opID, Err: err}
		}
		return fmt.Errorf("read %s response: %w", verb, err)
	}
	if !resp.OK {
		if mutation && (resp.Cause == "outcome_pending" || resp.Cause == "outcome_unknown") {
			return &UnknownOutcomeError{OpID: opID, Err: &RemoteError{Cause: resp.Cause, Message: resp.Message}}
		}
		return &RemoteError{Cause: resp.Cause, Message: resp.Message}
	}
	if out != nil && len(resp.Payload) > 0 {
		if err := json.Unmarshal(resp.Payload, out); err != nil {
			if mutation {
				return &UnknownOutcomeError{OpID: opID, Err: err}
			}
			return fmt.Errorf("decode %s response payload: %w", verb, err)
		}
	}
	return nil
}

// AllocateNetwork allocates a per-VM network namespace and TAP device.
func (c *Client) AllocateNetwork(ctx context.Context, req AllocateNetworkReq) error {
	return c.call(ctx, "allocate_network", "", req, nil)
}

// ReleaseNetwork tears down the network resources for a VM.
func (c *Client) ReleaseNetwork(ctx context.Context, req ReleaseNetworkReq) error {
	return c.call(ctx, "release_network", "", req, nil)
}

// StartVM launches a jailed Firecracker VM and returns its process identity.
func (c *Client) StartVM(ctx context.Context, req StartVMReq) (StartVMResp, error) {
	var resp StartVMResp
	if err := c.call(ctx, "start_vm", "", req, &resp); err != nil {
		return StartVMResp{}, err
	}
	return resp, nil
}

// SignalVM sends a signal to a running VM process.
func (c *Client) SignalVM(ctx context.Context, req SignalVMReq) error {
	return c.call(ctx, "signal_vm", "", req, nil)
}

// ReleaseVM removes the VM's jail directory and cleans up resources.
func (c *Client) ReleaseVM(ctx context.Context, req ReleaseVMReq) error {
	return c.call(ctx, "release_vm", "", req, nil)
}

// NetworkLeases reads the daemon's authoritative subnet claims.
func (c *Client) NetworkLeases(ctx context.Context) (map[string]string, error) {
	var out map[string]string
	err := c.call(ctx, "network_leases", "", nil, &out)
	return out, err
}
