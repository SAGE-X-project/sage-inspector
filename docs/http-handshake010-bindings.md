# HTTP handshake and authenticated loopback TLS

Both cores now support HTTP-bound initiation and completion, followed by HTTP-bound
session requests/responses. Bind the completion endpoint before any handshake
attempt; bare APIs reject after binding. The exact HTTP request is retained for
response `;req`, and both signatures precede one handshake replay reservation.
Pending state is one-shot: an attempted invalid HTTP completion closes it.

The new raw HTTP/1.1 codecs receive original field occurrences and content bytes.
They compare origin-form path/query and Host against trusted endpoint configuration,
extract response status, enforce exact canonical Content-Length, and reject
ambiguous framing, obs-fold, duplicate critical fields, transfer coding and
header injection. Raw fields are limited before whitespace removal, so large
optional whitespace cannot evade the field budget. Content and decoded signature
limits remain in force. These are stricter admission rules than a general-purpose
HTTP implementation, informed by [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
sections 3, 5 and 6 and the existing SAGE chapter 03 profile.

## What actually runs

- 22 shared handshake unit scenarios and 24 offline framing rejection categories,
  plus exact raw field-size boundaries, in each core.
- 88 real CLI process scenarios across Go/Go, Go/Rust, Rust/Go and Rust/Rust.
  Python/Node independently verify HTTP bases, envelope signatures, completion
  signatures and transcript/request binding. A synthetic store exposes separate
  handshake and record reservation counters; outer authentication does not create
  an extra reservation. A delayed handshake commit may retain a denial entry
  without producing a session, preserving the existing conservative contract.
- 16 loopback TLS scenarios: successful exchange, signed application error,
  untrusted CA and wrong hostname for each core pair. Successful cases exchange
  handshake and encrypted session records over fresh TCP/TLS connections to the
  same configured loopback endpoint. Incoming bytes go through the actual core
  codec and cryptographic API, not an Inspector substitute verifier.
- TLS 1.3, verified server certificate and hostname, and ALPN `http/1.1` are observed.
  A fresh private test CA and server certificate live only in a temporary directory;
  no trust store is modified. Untrusted CA and hostname mismatch produce zero HTTP
  handler invocations and zero core reservations.
- Eight offline tests verify the fixture transport's byte handling, duplicate-field
  preservation, body/header bounds and absolute read deadline. Adapter input tests
  cover the raw HTTP control sizes while keeping previous control limits intact.

Malformed framing is tested offline only. Runtime sockets carry ordinary valid
HTTP messages or normal TLS certificate failures, use only 127.0.0.1 and have
bounded connections, messages and deadlines. No external targets, production
credentials, host bypass or attack-capable reproduction programs are used.

## Evidence and limits

The CI builds these reviewed, merged revisions:

| Core | Revision |
| --- | --- |
| Go | `6fc763bb2afa45ace356f39de895254decee7103` |
| Rust | `d5bb16261edadfda6f33e8e769fe029472538513` |

The transport is an Inspector Python/OpenSSL fixture, not a production Go/Rust TLS
service. Core parsing and cryptography execute in their real processes. A deployed
caller must still enforce authenticated TLS, trusted routing and one-message
connection ownership; never deserialize untrusted peer JSON as transport metadata.
The fixture reads exactly one declared frame and closes the connection, so leftover
bytes cannot become a second dispatch. HTTP/2, HTTP/3, keep-alive/pipelining,
chunking, broader Structured Fields/URI normalization and proxy integration remain
unsupported by this bounded codec. TLS integrity does not replace application
validation or protect a fully compromised trusted endpoint by itself.

Run `scripts/test_http_tls010_unit.py`, then `scripts/test_http_handshake010.py`
with `--go`, `--rust` and a new `--output` directory. The default mode enforces
clean, pinned core revisions and equal shared fixtures. Development runs require
an explicit flag and are not CI acceptance evidence.

`report.json` records core/executable/fixture hashes, the TLS library, public test
certificate hash, 88 process results and 16 TLS results. TLS evidence includes
negotiated protocol, ALPN, certificate/hostname verification and received-byte
hashes. `raw.jsonl` preserves bounded core control exchanges and exits; its hash
is recorded in the report. The CI artifact adds the tenth report group,
`http-handshake010`, while retaining all previous regressions.

Historical HTTP FAIL/UNSUPPORTED and other archived results remain unchanged.
Production replay persistence/quarantine, chain finality, host enforcement and
full protocol conformance are not established by these tests. The next work is
broader Structured Fields and URI interoperability with independent RFC vectors,
followed by WebSocket and deployment boundaries.
