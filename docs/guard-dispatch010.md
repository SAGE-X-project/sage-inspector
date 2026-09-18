# Serialized Guard dispatch for 0.10.0

Both cores now provide a DispatchGate that owns durable execution storage and trusted
current authority, policy and pinned component bindings. Verification, configuration
replacement, permanent retirement and bounded execution commitment share one mutex.
No verified snapshot or reusable execution token escapes the gate.

A new authenticated call reserves call and nonce, persists EXECUTING, then freshly
checks key/signature, current policy, measured component and time before commitment.
The same pinned object receives exact canonical signed intent and arguments. A repeat
returns authenticated storage metadata without committing again. Final denial or
uncertain commitment leaves UNKNOWN; storage failure fails closed. Callback panics
also retire the gate. Retirement prevents later commitments and replacement cannot
reactivate it. A previously committed invocation keeps its pinned instance.

## Trust and completion boundaries

Component.Check and Component.Commit are trusted host integration seams. The host
must bind approved measured bytes and covered dependencies to the same immutable
loaded instance. Commit is a bounded atomic handoff into that instance's protected
execution boundary, not unbounded tool execution while holding the mutex. No name/path
reopening or unsigned defaults may occur. Actual queued work retains the exact pinned
instance and arguments. Missing/error decisions deny; providers must use bounded
callback deadlines, fresh registry observations and trusted time.

Policy/component changes must use the same gate. Protected administrative approval,
old/new baseline audit records, durable retirement across restart and all receivers,
production immutable loaders and capability isolation are host duties. Local retirement
cancels uncommitted work; already committed effects cannot be rolled back. A remote
cancellation remains a separately authorized protocol operation. No host-bypass or
external attack reproduction code is included in this work.

The receipt contains only created/committed flags, stored state and intent digest.
It is not a signed result or a completion guarantee. Signed pending/terminal publication,
durable first terminal storage, client single consumption, MCP mapping, deployed Source
and host certification remain outstanding. The existing 37 lifecycle scenarios remain
NOT_RUN and full conformance remains NOT_ESTABLISHED; this bounded gate evidence does
not promote them to PASS.

## Verification and reproducibility

Native unit tests check final key/policy/time/component denial, cancellation, panic and
uncertain commitment, immutable arguments, one commitment among concurrent duplicates,
and serialized retirement/replacement ordering. No external tool runs in these tests.

The Inspector runtime uses 30 bounded local processes: 20 per-core scenario runs, eight
processes across all four writer/reader recovery pairs, and two missing-ledger controls.
Fixture components measure owned immutable bytes and only record an inert handoff.
Python independently checks exact canonical intent/proof, arguments, component instance,
manifest commitment, intent digest, created/committed flags, journal identities and
state rows. Recovery preserves UNKNOWN and produces zero new commitments. Three offline
evidence tests reject altered arguments/instance/proof, false commitments and false
completion observations.

Run `scripts/test_guard_dispatch010.py` with --go, --rust and a new --output directory.
CI requires pinned core revisions and preserves raw requests/responses, exit status,
28 journal snapshots, binary hashes and 58 evidence-file hashes in a separate
`guard-dispatch-bindings` artifact. Development runs are explicitly marked. Existing
reservation, primitive and 14 record-runtime report groups remain separate; historical
evidence is not overwritten or reclassified.
