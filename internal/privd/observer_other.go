// ABOUTME: Refuses network observer acquisition on platforms without Linux netlink.
// ABOUTME: Keeps the portable daemon and runner builds honest about unsupported collection.
//go:build !linux

package privd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func (c *Client) AcquireNetworkObservers(context.Context, AcquireNetworkObserversReq) (*NetworkObserverBundle, error) {
	return nil, fmt.Errorf("network observers require Linux")
}
func (s *Server) handleObserverConn(conn *net.UnixConn, _ Request, _ json.RawMessage, framing time.Duration) {
	_ = conn.SetWriteDeadline(time.Now().Add(framing))
	_ = WriteMsg(conn, errResp("unsupported", "network observers require Linux"))
}
