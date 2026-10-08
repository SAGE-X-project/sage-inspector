# Native protected hop execution observation

This separate observation pins Go
`1aaee98258e72aeeaba5a8c49fc9908b41ff29cd`, Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb` and normative source
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. Its report is
[hop-execution.json](hop-execution.json) and its independent artifact oracle is
[inspect_hop_execution.py](../../scripts/inspect_hop_execution.py). The preceding
[issuance observation](hop-issuance.md), all source catalogs and historical
verdicts remain unchanged.

`LOCAL_NATIVE_HOP_EXECUTION_BOUND` records actual A-to-B-to-A transport in three
separate localhost processes. All eight Go/Rust combinations use the public
native MCP APIs. A issues a protected root to B; B's admitted Invocation supplies
the actual parent authority for independent child approval, signing and existing
journal handoff. A separate A receiver reserves and executes the fixed inert
read exactly once. B consumes A's signed child result, then the root Client
consumes B's signed result containing
`{"child_status":"completed","output":{"ok":true}}`.

Eight ordinary refusal observations use the two alternating language chains.
Own policy, loaded-component measurement and signing refusals occur before
child connection, reservation or execution. Receiver preparation refusal
performs native setup and reaches the leaf preparation boundary, but creates no
child transport attempt, reservation, execution or terminal delivery. The root
forwarding operation returns the authenticated output
`{"child_status":"denied","output":null}`. Its procedural completion does not
claim that a refused child operation executed successfully.

The Inspector separately verifies exact upstream bytes, parent call, framed
original commitment, own policy and manifest, role-bound Ed25519 proofs, the
pre-signing fence and one-use approval. It checks the same append-only child
journal before and after handoff, fresh outer attempt IDs, retry cadence,
terminal identity, result intent digest, actual consumed output and the leaf's
exact RESERVED/EXECUTING/COMPLETED ledger. The root result time follows the
middle process's measured child clock advances; the leaf result uses its own
clock. Retained native parent authority refuses after worker/host completion.
These assertions reject changed saved artifacts even if re-signed with the
public fixture keys. They are not signed deployment attestations.

Replay-store recovery uses genuine public native HPKE bootstrap exchanges.
New journals and endpoints are created at logical time zero, both logical clock
dimensions advance through the 360-second quarantine, and native Start, Respond
and Complete execute. Stores close before public reopening. The report retains
both wire envelopes and corresponding replay rows. The artifact oracle verifies
canonical outer signatures, roles, request/response correlation and exact replay
rows. It does not independently verify the complete HPKE transcript, exporter or
ACK and leaves `outer_handshake_oracle` as `NOT_RUN`. Bootstrap establishes
fixture store readiness, not an application effect or a fabricated READY flag.

The component returns an in-memory `{"ok":true}` and never opens the requested
`public.txt`. Registry validation/finality, key custody, component appraisal,
clock and policy remain local fixtures. The leaf obtains exact admitted-parent
context from a shared private run directory; protected acquisition of that
context is assumed, not proven for a deployed host. Separate processes do not
establish compromise isolation. No authoritative blockchain Source, selected
Agent deployment, ADK loader, thirteen deployed-host controls, complete normative
case, INS-11 or organizational audit is closed. Full conformance remains
`NOT_ESTABLISHED`; deployed independent hop execution remains `NOT_RUN`.

Both external programs compile against clean pinned cores. Adapter bytes,
selected source hashes, full clean revision checks and existing dependency locks
are checked before and after runtime observations. Artifact-only refusal units
send no changed network messages. The runtime sends fixed benign requests and
exercises ordinary local provider refusals; no arbitrary tool or shell execution
or attack-capable reproduction is included.

Check the saved evidence and 35 refusal units:

```sh
python3 -B scripts/inspect_hop_execution.py
python3 -B scripts/test_hop_execution.py
```

For sixteen fresh runtime observations, use clean cores at the above revisions,
cached public dependencies and the existing pinned Rust core lock from
`verification/0.10.0/intent-issuance/Cargo.lock`:

```sh
python3 -B scripts/inspect_hop_execution.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/hop-execution.json
```

The [workflow](../../.github/workflows/hop-execution.yml) repeats the saved checks,
units, clean source checks, public builds and sixteen fresh observations. Continue
with actual Registry and protected host/provider selection, then independently
observed deployment/effects in the approved order. This report does not select
the Sepolia candidate or resolve its 21 Registry obligations, and does not start
later contract upgrades, demos or normative A2A/DID amendments.
