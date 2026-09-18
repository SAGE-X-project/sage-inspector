# Authenticated Guard reservations for 0.10.0

Both cores now privately project freshly verified signed intents into durable call
and nonce reservations. The Guard wrapper owns the store and recipient; it accepts
no raw Entry or cached verification flag. Exact retries preserve the whole canonical
envelope including proof and return stored state without transitioning or appending.
Fresh authority, current policy and trusted time apply on every call, including
retrieval. Expiry during storage denies the response while retaining durable state.

The response is local metadata: created, state and intent digest. It is neither a
signed pending/terminal protocol response nor dispatch permission. Stored terminal
bytes are not exposed. Normal recovery never creates missing state; RESERVED and
EXECUTING become UNKNOWN and cannot be re-reserved or promoted to completion.

## Verification

Native tests cover independent signed-intent vectors, correctly signed identity and
proof conflicts, nonce reuse, concurrent identical calls, fresh authority denial,
expiry during storage, missing/exclusive/closed storage, and storage write failure.
Low-level tests verify unchanged retrieval of every existing execution state.

`test_guard_reservations010.py` runs 16 bounded local processes: six per-core scenario
runs (retry, current-authority denial, initial denial), two missing-ledger controls,
and eight processes across four writer/reader language pairs. Python independently
checks exact stored identity fields, complete canonical intent bytes, row counts,
created flags and UNKNOWN recovery. Three offline report tests reject altered
projection, duplicate reservation and false completion observations. Adapters use
fixture authority callbacks only; they are not deployed registry or policy services.

Each new output directory retains raw requests, responses, process exit status,
journal snapshots, source revisions, binary hashes and file hashes. CI checks pinned
source revisions and preserves a separate `guard-reservation-bindings` artifact.
Historical evidence and the existing 14 record-runtime report groups are unchanged.
Development runs are explicitly marked and do not establish pinned-source evidence.

## Remaining boundaries

The 37 Guard lifecycle scenarios remain NOT_RUN and full protocol conformance remains
NOT_ESTABLISHED. Final dispatch must serialize current policy retirement and loaded
component identity with execution. Signed pending/terminal publication, one-time
client consumption, MCP mapping, deployed validating Source and host isolation remain
unimplemented integration boundaries. This test harness creates no attack-capable
reproduction program and certifies no power-loss, rollback or compromised-host safety.
