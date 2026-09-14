# Registry, identity and Card inspection for 0.10.0

The Inspector now has 94 independent cases and 17 persistent scenarios (83 steps)
for the mandatory Ed25519 path, X25519 endorsement, DID syntax, Card verification,
key selection, inactive resolution, authoritative observation and basic lifecycle
mutation. This completes the planned Inspector preparation for these boundaries;
it does not certify current cores or any deployed registry.

## Current observations

| Core | PASS | FAIL | UNSUPPORTED | Stateful scenarios |
|---|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 | 23 | 8 | 63 | 17 NOT_RUN |
| Rust 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 23 | 8 | 63 | 17 NOT_RUN |

See [evidence/registry](evidence/registry) and its source/tooling provenance.
The eight failures are the same on both cores: three canonical new DID forms are
rejected, the legacy ethereum/eth/solana forms are accepted, a correct new PoP is
rejected, and a legacy PoP is accepted. Both overall reports are FAIL.

Adapters invoke actual public ValidateDID/validate_did and
VerifyKeyProofOfPossession/verify_key_pop APIs. These APIs implement historical
syntax and a SHA256 digest of `SAGE-PoP:<DID>:<hex key>` rather than the new
length-prefixed challenge. The old PoP API has no key-name parameter; the adapter
does not invent a name-binding check. `supported_kinds` is explicit normative
fixture configuration, but cannot configure the legacy parser. Signature-only
cases use the existing real core signature API on independently computed bytes.
Their PASS does not establish record, Card, authority or lifecycle verification.
Current record/Card/KEM/authorization/projection operations have no matching
0.10.0 API and return UNSUPPORTED; no model is substituted for those APIs.

## Independent fixtures and coverage

[generate_registry_vectors.py](../scripts/generate_registry_vectors.py) uses
Python cryptography and public deterministic Ed25519/X25519 test keys. It imports
neither core. [check_registry_vectors.js](../scripts/check_registry_vectors.js)
independently rebuilds PoP and Card signing inputs, checks signatures with Node,
validates the deliberately bounded fixture shapes, recomputes observations with
an abstract model, and verifies case uniqueness and manifest hashes. The fixture
JCS inputs have ASCII member names and safe integer numbers; the broader JCS and
strict curve/subgroup suites remain separate prerequisites.

| Boundary | Cases and meaning |
|---|---|
| ID-01/02 | Canonical web/eip155, 64/65-byte agent ID, legacy aliases, reserved solana, uppercase kind/domain/address, leading-zero chain, extra locator, empty/dot/Unicode/percent/query/fragment rejection. DID URLs belong to a separate contract, not this bare-DID operation. |
| REG-04 | Signing PoP and KEM endorsement with registry/agent/name domain mutations. Historical revoked/expired signing keys may verify a retained KEM endorsement on read, but cannot endorse a newly added KEM key or authenticate a message. A second usable signing key keeps those fixture records active. |
| REG-01/02 | Version bounds, immutable-name/material uniqueness, ordering, proof presence, canonical encoding, service/key collisions, unsafe service URLs and exact named signing keys. ASCII-first usable KEM selection skips expired/revoked keys; no KEM does not imply an invalid signing identity. |
| CARD-01..03 | Exact proof domain including proof metadata, peer/services/version binding, trusted clock, equality expiry, maximum lifetime, display bounds, duplicate/unsorted capabilities, legacy proof labels, unknown/null members, wrong key and actual signature tampering. Invalid semantic Cards are re-signed so signature failure cannot hide those boundaries. |
| RESOLVE | Created/deactivated records remain readable; their key relationship arrays are empty and authentication fails. Resolution projection is deliberately smaller than a full DID document/JWK/HTTP representation. |
| REG-05 | At-most-five-second operation snapshot, operation-start ordering, no positive cache reuse, persistent highest finalized version, rollback, conflicting observations, wrong source/registry, unavailable clock/source/record, mixed block hashes, restart readiness, finalized tombstones and unfinalized revocation followed by reorg. |
| REG-03 | Explicit controller authorization, expected-version CAS, one version increment on success, no change on failure, terminal deactivation. Full deployment mutation/commit-reveal/operator administration is not emulated. |

`registry-records.json` is schema1. Every positive returns `{valid:true}` except
KEM selection (`{keyid:fullURL}`) and inactive resolution's documented projection.
Every rejection returns an empty object. Operations:

- `sage.did.validate`: did plus explicitly enabled supported_kinds.
- `sage.registry.pop.verify`: did, name, alg, public_key_hex, signature_hex.
  This delivery projects the existing Ed25519 API; optional algorithms are not
  silently mapped to a different digest or signature convention.
- `sage.registry.record.verify`: raw record_hex, expected_did, now, mode read or
  add-kem. An add-kem check tests current endorser eligibility, not controller
  authorization; that authorization is measured separately in state scenarios.
- `sage.registry.authenticate`: validated record, exact keyid, sender,
  expected_peer, alg and now. ACCEPT means selection eligibility, not verification
  of an absent application message signature.
- `sage.registry.kem.select`: validated record and now, returning the selected
  full URL only after active-state and usability checks.
- `sage.card.verify`: raw card_hex, controlled record, now, clock_trusted and
  expected_peer. The fixed record is an explicit test seam for fresh authoritative
  resolution; real freshness is exercised independently by the scenario contract.
- `sage.registry.resolve`: validated record and now -> state, version,
  verification_methods, authentication, assertion_method, key_agreement and
  services. This inactive projection asserts no algorithm-bearing methods exist;
  it does not claim complete DID Core/JSON-LD/JWK interoperability.

Malformed adapter IPC (missing/null strings, invalid hex) is an execution error,
not a peer REJECT. The 4MiB runner input bound and process timeout remain in force.
Record service validation never fetches the URI. Card text/capabilities are never
executed and supply no authorization or alternate key source.

## Authority and state instrumentation

Schema2 fixtures run one persistent process each. No expectations, counters or
future steps are sent. Missing bindings/instrumentation must return UNSUPPORTED;
subsequent steps remain NOT_RUN. The optional combined runner leaves all scenarios
NOT_RUN unless an actual state adapter is explicitly supplied.

`control.registry.create` sets a synthetic eip155 record with correctly bound
PoPs, fixed controller, a trusted source identity and initial readiness. It is
preparation of an isolated test registry, not proof that a blockchain registration
occurred. `subject.call` actions have these meanings:

- observe: obtain the controlled authoritative observation through the actual
  subject's resolver/authorization boundary. Inputs explicitly state source,
  registry_id, readiness, trusted-clock status, operation_started/observed/gate
  monotonic seconds, finalized version/state and record/keys block hashes.
  lookup/transport_ok/conflicting represent faults at that seam. They are trusted
  harness controls, never peer assertions accepted as authority.
- authorize: the same observation followed by the real active-record gate.
  A readable deactivated record is not an authorized operation. The observation
  can update a finalized version/tombstone even when authorization then rejects.
- restart: restart subject state within the persistent adapter, preserving highest
  finalized versions and confirmed tombstones; readiness becomes false. ready
  explicitly re-establishes readiness through the subject's source seam.
- mutate: invoke activate/deactivate as selected by new_state, with explicit
  authenticated-controller result and expected_version. Report actual version/state.
- inspect: report highest_finalized_version, tombstone, ready, management version
  and state. Effects are cumulative observations, authorized and mutations.

Management version/state and observed version/state are separate in these
fixtures: the authority can advance independently of this client's mutations.
Observation control versions denote already validated record snapshots. Complete
record validation is tested by the primitive contract; the observation model does
not manufacture signatures or chain evidence. An implementation binding must
actually intercept those subject boundaries and observe the resulting effects.

The five-second equality case is allowed (`at most 5`); six seconds fails. An
observation before the operation starts cannot authorize it even if younger than
five seconds. Unfinalized revocation denies that operation without becoming an
irreversible tombstone; a subsequent finalized active snapshot can succeed.
Finalized tombstones and the highest finalized version survive restart. A source
saying “latest”, TLS alone, or a field named finalized is not a finality proof.

## Run and remaining assurance

```sh
go build -o /tmp/sage-conformance ./cmd/sage-conformance
go build -o /tmp/sage-scenario ./cmd/sage-scenario
node scripts/check_registry_vectors.js
python3 scripts/test_registry_inspection.py
python3 scripts/inspect_registry.py --runner /tmp/sage-conformance \
  --adapter /absolute/core-adapter --subject sage-go --revision ACTUAL_REVISION \
  --output-dir /new/evidence-directory
```

Add both `--scenario-runner /tmp/sage-scenario --state-adapter /absolute/state-adapter`
when a real binding is available. Existing output directories are not overwritten.
The manifest ties case/scenario identities and hashes to rules. The combined
report validates subject identity, membership, expected/actual values, effects,
process outcome and evidence hashes. Exit0 PASS,1 FAIL,2 ERROR,3 INCOMPLETE.

Real chain finality/readiness, deployed code hash/upgrade policy, ABI, operator
scope, transaction/commit-reveal behavior, web TLS/cache/redirect/SSRF enforcement,
publication-to-finality latency and full DID consumer interoperability require
explicit deployment bindings and measured evidence. They are not given zero
latency or a PASS by these fixtures. Optional algorithm registration remains
separate from mandatory Ed25519 inspection. The 386 baseline planned cases are
not auto-promoted to PASS. Registration does not attest loaded code or user intent,
and a malicious trusted authority is outside this declared boundary.
