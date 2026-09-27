# Current-spec HPKE initiation binding

HPKE-02 defines the exact initiation fields and derives the HPKE `info` and
exporter context from a canonical B object. B contains the version, context,
both participant DIDs, their selected signing keys, the responder KEM key,
suite, combiner, and nonce. The task name, encapsulation, and independent
X25519 public value are excluded from B. The authenticated envelope must
match the participant and context fields, and the nonce must be fresh.

Five revision-bound Inspector fixtures cover this rule. The positive fixture
uses the existing SAGE schedule's canonical initiation, independently rebuilds
B, `info`, and `exportCtx`, and checks their equality to the existing exporter
vector before submitting that exporter operation to each core. Four denial
fixtures change one trusted condition at a time: authenticated initiator DID,
authenticated context ID, previously seen nonce, and selected responder
signing key. Their expected effects are zero created sessions and zero
protected dispatches. All fixtures use deterministic local test values.

The positive operation proves only the fixed HPKE exporter output for the
given bytes. It does not prove that an implementation generated fresh,
independent encapsulation and X25519 keys, authenticated the envelope,
checked nonce history, or rejected a changed identity or key. The current
core adapters do not expose `sage.hpke.init.verify` or its effects, so the
four denials must remain `UNSUPPORTED`. A complete HPKE-02 result requires
an authenticated initiation entry point and session/dispatch observation.

The [preserved Go/Rust run](evidence/current-spec/hpke02/) pins the spec,
both core revisions, and Inspector runner. Recheck fixture relations,
runner hashes, all observations, and assessments with
`python3 -B scripts/check_current_spec_hpke02_evidence.py`.

The exporter output matches in both cores, so HPKE-02-P is `PARTIAL` in each.
HPKE-02-N01 through N04 are `UNSUPPORTED`. Overall conformance remains
`NOT_ESTABLISHED`.
