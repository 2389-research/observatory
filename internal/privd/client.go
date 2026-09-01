// ABOUTME: Dial-per-call privd client: one unix-socket connection per request.
// ABOUTME: Each call dials, writes the request, reads the response, and closes.
package privd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
)

// Client is a privd client. SocketPath is the path to the privd unix socket.
// All methods dial fresh for each call (one request per connection).
type Client struct {
	SocketPath string
}

// call is the shared request/response helper for all verb methods.
func (c *Client) call(ctx context.Context, verb, opID string, payload, out any) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("dial privd %s: %w", c.SocketPath, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", verb, err)
	}
	if err := WriteMsg(conn, Request{V: ProtoVersion, Verb: verb, OpID: opID, Payload: raw}); err != nil {
		return fmt.Errorf("send %s: %w", verb, err)
	}
	var resp Response
	if err := ReadMsg(conn, &resp); err != nil {
		return fmt.Errorf("read %s response: %w", verb, err)
	}
	if !resp.OK {
		return &RemoteError{Cause: resp.Cause, Message: resp.Message}
	}
	if out != nil && len(resp.Payload) > 0 {
		if err := json.Unmarshal(resp.Payload, out); err != nil {
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
