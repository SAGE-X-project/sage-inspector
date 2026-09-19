# MCP authenticated session bindings

The Go and Rust cores carry exact non-HTTP MCP RPC bytes through the existing
signed AEAD session records. This adds no wire fields or cryptographic primitive.
The plaintext limit remains 16,348 bytes. HTTP chapter 08 intent-payload mapping
and authenticated MCP initialize negotiation are separate requirements.

## Core integration

Go exposes `SealMCPSessionRequest`, `OpenMCPSessionRequest`, and `MCPSessionCall`;
Rust exposes their snake-case equivalents. A call retains the authenticated peer,
exact request, original intent, inner RPC UUID and distinct outer message ID.
Incoming calls expose authenticated request bytes and their RPC ID to the existing
Guard endpoint. Replies must match the original intent, identities, RPC ID and
protected success/error mapping. Response permits prevent repeated publication
or delivery. Cryptographic replay acceptance is not rolled back when subsequent
application validation fails.

Transport authentication does not verify the inner Guard proof or authorize an
effect. The host must route the opened request through `MCPEndpoint` and route the
opened reply through the durable Guard client. It must also retain endpoint attempt
history, establish authenticated MCP version negotiation, and protect every effect
path. A copied request is not a portable execution permit.

## Verification and evidence

```sh
python3 scripts/test_mcp_session_reports.py
python3 scripts/test_mcp_session010.py --go /path/to/sage-completion010 \
  --rust /path/to/completion010 --output /tmp/new-mcp-session-results
```

Core unit tests cover identity, invocation, intent, size and invalid-permit cases.
Five Inspector report tests reject changed bytes, correlation, peer and result
mapping inconsistencies using offline synthetic observations.

Runtime checks start eight bounded local core processes for Go→Go, Go→Rust,
Rust→Go and Rust→Rust. Each pair exchanges pending and completed results over
real authenticated sessions, for eight exchanges. Exact whitespace-bearing RPC
bytes survive encryption/decryption. Duplicate request reception, duplicate reply
publication/consumption and a reply presented to a different invocation are rejected.
The independent Node verifier checks 32 outer and inner signatures, in addition to
handshake verification. All keys are public test fixtures; no remote host or tool
is invoked.

The CI artifact `mcp-session-bindings-<revision>` contains the report and 11 hashed
files: exact intent, eight registry journals, raw process observations and signature
inputs. It records pinned core revisions and adapter binary hashes. Existing
historical evidence is preserved. `--development` explicitly marks unpinned runs.

The fixture uses controlled registry observations, an in-memory replay store and
trusted MCP version configuration. This transport test does not execute Guard
dispatch or durable client consumption; both remain `NOT_RUN` in this report.
The complete 37 lifecycle scenarios remain `NOT_RUN`, and full conformance remains
`NOT_ESTABLISHED`. Source review similarly remains `INTEGRATION_NOT_VERIFIED`
for an operational deployment.

Next, connect this protected transport to actual Guard dispatch and durable client
consumption in a bounded local runtime, then establish authenticated setup and
host enforcement evidence. Transport-only results do not complete those tasks.

The subsequent [protected Guard flow](guard-session010.md) now connects actual
Guard dispatch and durable client consumption through this transport in a controlled
local runtime. This earlier transport-only report retains its original scope.
