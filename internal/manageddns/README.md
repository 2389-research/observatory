# Managed DNS

`New(DefaultConfig(explicitUpstream), sockets)` constructs a worker without
opening sockets. Run it once with `Run(ctx)`; wait on `Ready()`, drain
`Observations()`, and poll `Status()` independently of event persistence.
Cancellation closes both listeners, accepted clients and owned upstream TCP
connections, joins producers, and closes the observation channel. An unexpected
listener failure returns an error and shuts down the other listener too.

The integration layer supplies namespace-bound UDP/TCP53 listeners and two
upstream adapters. Both adapters must target only `Config.Upstream`, respect
context deadlines/cancellation and bounded messages, and support concurrent
calls up to `MaxConcurrent`. `ExchangeUDP` owns its sockets and must validate the
upstream sender; use a connected socket or check its source explicitly. A shared
UDP adapter must safely multiplex request IDs or serialize exchanges. `DialTCP`
transfers a connected socket to the worker. The worker never resolves names,
opens fallback sockets or chooses another upstream. Privd owns policy validation;
this package allows explicit loopback endpoints for real tests.

Defaults and hard ranges:

| Setting | Default | Allowed |
| --- | --- | --- |
| Active queries | 16 | 1–64 |
| Accepted TCP connections | 16 | 1–64 |
| Queries per TCP connection | 32 | 1–128 |
| DNS message bytes | 65,535 | 512–65,535 |
| Retained answer records | 32 | 1–128 |
| Queued observations | 128 | 1–1,024 |
| Queries per second | 100 | 1–1,000 |
| Burst | 100 | 1–1,000 |
| Query deadline | 3 seconds | positive, at most 30 seconds |
| TCP idle/frame deadline | 5 seconds | positive, at most 30 seconds |

A token bucket spans UDP and TCP and uses monotonic elapsed time. Saturated query
or rate limits produce REFUSED with local decision evidence. Excess connections
close immediately; admitted TCP connections process at most the configured number
of requests, sequentially, with fixed read deadlines that slow clients cannot
extend by trickling bytes. At most 2,048 wire questions/resources are parsed per
message, independently of retained answer limits. UDP replies respect the
client's EDNS size (512 without EDNS), configured size and IPv4's 65,507-byte UDP
payload maximum. Oversized answers become a valid TC response, not a byte slice
cut through a resource or compression pointer.

Only ordinary single-question IN queries with opcode QUERY are forwarded. The
worker rejects zone transfers, obsolete mail transfers, other classes/opcodes,
multiple questions, query answer/authority sections and additional records other
than a single EDNS OPT. Unsupported EDNS versions receive BADVERS. Valid EDNS
options, DNSSEC flags and other wire contents pass through unchanged; this worker
is not a recursive resolver, cache or DNSSEC validator. It validates QR, ID,
opcode and question (ASCII case-insensitive name, exact type/class) on every
upstream response, including actual TCP fallback after UDP TC. NXDOMAIN and
upstream REFUSED remain forwarded upstream outcomes, distinct from local refusal.
Malformed messages, duplicate OPTs, compression loops and trailing bytes fail
explicitly. Packets marked as responses never receive a response.

Evidence stores decimal-escaped byte names (`\255`, `\092`), preserving case;
it does not interpret arbitrary bytes as Unicode or guess a hostname. The
underlying dnsmessage parser rejects literal dots inside a label and excessive
compression indirection; these requests are explicit malformed-query outcomes
with no invented name. A/AAAA addresses and CNAME/NS/PTR/MX/SRV targets have typed
fields. Other answer RDATA, including TXT and DNSSEC material, is omitted and
marked `DataOmitted`; authority and additional RDATA are not retained. Answer
retention stops at `MaxRecords`, with `RecordsTruncated` evidence. No observation
contains raw DNS wire data. `ResponseTruncated` describes the reply's TC bit,
separately from observation retention and UDP-to-TCP upstream fallback.

`Status.Received` counts datagrams and complete TCP frames reaching admission.
`Completed` counts observations, including malformed TCP frames/connection
limits; it is not a successful-resolution counter. `Rejected` counts local
refusals. `Dropped` counts observations lost to the full channel; DNS service
continues, and live status remains readable. `RCode` is the validated upstream
code or a generated local rejection code; transport failures have no upstream
code, and messages receiving no reply have no code. `DeliveryError` records a
failed client write without pretending the resolution itself failed.

The runner must stamp immutable VM/boot/acquisition scope, convert uint64 values
to decimal strings for JSON, write through the existing durable spool, and
propagate spool failures into independent coverage. This package does not grant
readiness authority or activate firewall rules. Listener readiness does not
prove upstream reachability or durable observation acceptance.

Protocol references: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html),
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html), and
[Go dnsmessage](https://pkg.go.dev/golang.org/x/net/dns/dnsmessage).

Tests use real local UDP/TCP upstream servers and clients. Run
`env -u GOROOT mise exec -- go test -race ./internal/manageddns`, followed by
focused `go vet` and `golangci-lint run ./internal/manageddns/...`. The package
suite is not the privileged namespace or guest acceptance gate.
