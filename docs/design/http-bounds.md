# HTTP and terminal connection budgets

`vmobs` gives each request 30 seconds, including redirects and reading its body.
Put a positive Go duration before the command to override it, for example
`vmobs --timeout 2m doctor`. Zero and negative durations are usage errors.
Each request has a deadline context. The HTTP client also sets its overall and
response-header timeouts to that budget. Both system trust and `--ca` clone Go's
default transport, preserving its dial, TLS handshake and connection pool limits.
The custom CA bundle replaces the trust roots; it does not disable verification.

Responses are limited to 16 MiB after transport decompression. Overflow or a
failed body read produces exit code 2 and no partial output. The error names the
byte cap or read failure; narrow the query or use pagination for large results.
A CLI timeout does not prove that a mutating operation failed on the daemon.
Check the operation or VM state before retrying; retain any idempotency key.

The daemon allows 5 seconds for request headers and 30 seconds total for reading
a request, including its body. Existing JSON byte caps still apply. Keep-alive
connections expire after 60 idle seconds. `MaxHeaderBytes` is explicitly 32 KiB;
Go's HTTP/1 parser adds its small read-buffer allowance before refusing oversized
headers. These limits apply in loopback HTTP and TLS modes.

There is no blanket response write timeout. Upgrading a terminal WebSocket clears
the HTTP connection deadlines through Go's hijack path. The terminal relay sends
a WebSocket ping every 30 seconds and allows 10 seconds for the pong. A browser
may remain quiet indefinitely while it answers pings; a peer that stops answering
loses its attachment. The heartbeat cancels the relay and releases the attachment.
This does not kill the guest shell, so a reconnect can use the existing replay
and session rules.

`cmd/vmobs/http_bounds_test.go` exercises real HTTP and custom-CA TLS peers with
stalled headers/body, overflow, truncation, successful requests and a longer
timeout override. `cmd/vmobsd/http_bounds_test.go` exercises real HTTP/TLS sockets
for server header/body/idle budgets and header sizes, plus a WebSocket that
survives the ordinary HTTP deadlines. `internal/api/terminal_heartbeat_test.go`
checks quiet responsive and unresponsive peers with short heartbeat budgets.
The normal relay suite covers terminal protocol behavior; Linux end-to-end
terminal evidence remains a separate gate.
