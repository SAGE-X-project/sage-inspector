# MCP setup admission model

This finite model provides review evidence for the revised, unadopted non-HTTP
proposal at sage-spec `a70784d6c3415b08d344bc7705f738df977ad3f9`. The local
[snapshot manifest](../verification/0.10.0/mcp-setup-proposal/manifest.json) hashes
seven source artifacts. It is separate from the normative 0.10.0 snapshot and does
not adopt the proposal or update older source reviews.

## Executed scope

The model explores each local client and server owner with symbolic send completion,
one deferred setup frame, request-ID history, accepted replay markers, setup evidence
and a monotonic clock. It explores all reachable states in its finite domain until
a fixed point; reaching the 10,000-state safety limit fails instead of reporting a
truncated search as complete. Both roles must reach READY, and admission must be
reachable when the reduced capacity permits it, preventing vacuous success.

Independent transition monitors check that CLOSED never reopens, consumed history
never disappears, READY has the required setup evidence and final transition, and
no admission is published before READY or while deferred processing blocks it.
Scenario tests cover output preparation, queued replies, overflow, partial/failed
send, exact deadline, late callbacks after close, timer retirement, setup ID reuse,
inner rejection and denied authorization. Synthetic unsafe successor states verify
that the monitor rejects premature readiness/admission and lost replay state.

The CLI executes the Python model in a real bounded local process and preserves its
report. This is a model runtime test, not a real core, MCP peer or cryptographic test.
No network, protected tool effect or attack traffic is produced.

## Explicit abstractions and limitations

- Time is represented by 0, 29,999, 30,000 and 30,001 ms; callback and closure events
  represent selected interleavings, not arbitrary scheduler or clock behavior.
- History capacities 2 and 3 represent the two setup request IDs and one protected
  request. This does not prove behavior at the production 1,024-attempt bound.
- Inputs represent already authenticated message kinds. Signature, AEAD, JSON schema,
  exact descriptor comparison, byte limits and real key/peer provenance are not modeled.
- Client and server owners are explored separately. Network coupling, delivery/loss
  fairness, full session recovery, cryptographic replay durability and host mediation
  are not established. Only setup message kinds may occupy the symbolic deferred slot.
- The admission marker means a trusted Guard handoff could be permitted; it is not a
  tool execution or proof of policy approval, ledger persistence or result consumption.

The result is MODEL_CHECKED, with actual_core_execution false, external_review false,
protocol_execution NOT_RUN and conformance NOT_ESTABLISHED. All 40 proposed protocol
cases and the existing 37 lifecycle cases stay NOT_RUN. Unit/model success is neither
an external independent audit nor a proof that the protocol has no remaining holes.

## Reproduction

```sh
python3 scripts/test_mcp_setup_model.py
python3 scripts/check_mcp_setup_model.py --output /tmp/new-setup-model-evidence
```

The report includes the proposal revision and source hashes, model source hash,
Inspector revision, per-role state/transition counts, reachability and abstraction
bounds. Existing output and historical evidence paths are rejected. CI preserves
`mcp-setup-model-<revision>` separately from actual core runtime artifacts.

Next: independent external review and a trusted connection-owner API contract.
Before normative adoption or core implementation, reconcile the proposal with the
existing local normative baseline and traceability. Model results alone do not
satisfy that gate; future core unit and real interoperability tests remain necessary.
