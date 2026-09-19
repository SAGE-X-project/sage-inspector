# Protected Guard flow verification

The Inspector connects actual durable client, authenticated session and Guard
endpoint APIs using trusted local orchestration. The Go and Rust cores are unchanged.
Four client/server language pairs execute the same flow; each side's session and
Guard adapter use the same language and existing public Guard fixture identities.
The optional `guard-fixture` completion adapter argument selects only those fixed
public test identities and keys. The default completion fixtures are unchanged.

## Observed flow

1. The durable client authorizes the exact intent and emits its MCP RPC request.
2. The session adapter protects those exact bytes. The receiving session authenticates
   them and supplies its authenticated RPC ID and bytes to the actual Guard endpoint.
3. Guard commits one inert effect with the authorized arguments and records execution.
   Its signed pending result travels through the reverse protected session and client.
4. Guard commits the signed completed result. A new RPC ID polls the same original
   intent after the polling interval. The ledger returns completion without another
   effect, and the client verifies and durably consumes the protected reply once.
5. A new client process reopens the same journal. It refuses another invocation and
   repeated terminal consumption, leaving the terminal journal bytes unchanged.

The runtime checks eight protected exchanges, four restarts and twenty actual core
processes. It rejects duplicate protected requests, duplicate response consumption,
repeated RPC reply publication and repeated client delivery. Server effect records
must contain exactly one authorized instance, tool and argument set. The execution
journal must show RESERVED → EXECUTING → COMPLETED; client journals must contain
the exact send/close/terminal sequence. Independent Node checks verify 44 signatures,
including handshakes, outer records, intent and actual Guard results. Result semantic
checks also bind each proof to its original intent and expected output.

Five offline unit tests cover evidence rejection for missing/repeated effects,
changed arguments, false dispatch states and missing terminal persistence. Existing
MCP report controls continue to check exact byte, identity and invocation bindings.

## Reproduction and evidence

```sh
python3 scripts/test_guard_session_reports.py
python3 scripts/test_guard_session010.py \
  --go-session /path/to/sage-completion010 --rust-session /path/to/completion010 \
  --go-server /path/to/sage-guard-results010 --rust-server /path/to/guard_results010 \
  --go-client /path/to/sage-guard-client010 --rust-client /path/to/guard_client010 \
  --output /tmp/new-guard-session-results
```

The CI artifact `guard-session-flow-<revision>` retains the report and 21 hashed
files: fixture, 16 journals, process observations and three signature evidence files.
The report pins core revisions and all six executable hashes. Failures retain partial
observations, and existing output directories and historical evidence are protected.

This is a controlled local integration, not a production host adapter. The trusted
orchestrator carries local IPC between separate session and Guard processes. Effects
are inert; authorities are controlled fixtures, session replay storage is in memory,
and MCP initialization is a trusted configuration. The client restart does not claim
transport reconnection, server recovery or complete mediation of host effect paths.
It also does not add the chapter 08 HTTP intent/RPC mapping.

Dispatch and durable consumption are PASS for this bounded flow. Historical reports
retain their original scope, including the transport-only NOT_RUN fields. The full
37 lifecycle scenarios remain NOT_RUN and full conformance remains NOT_ESTABLISHED.
Next is the authenticated MCP setup/version-negotiation boundary, followed by selected
host enforcement and recovery evidence. New protocol requirements require a separate
specification decision rather than being invented in an Inspector adapter.
