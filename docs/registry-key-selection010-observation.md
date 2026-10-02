# Registry signing-key selection observation

The [seven-case suite](../vectors/0.10.0/registry-key-selection010.json)
tests the key-choice portion of 0.10.0 ID-03 and REG-02 against both core
Registry Gates. The expectations are fixed in Inspector and derived from
`sage-spec` revision `fa006fd917ad365eb554a27f4178301cd66e2379`.

The positive control selects the exact active signing key. Negative controls
request an absent key, a revoked or exactly expired key while another signing
key remains usable, a KEM key in the signing role, an inactive record, and a
session requiring an unavailable KEM key. Each case runs in its own bounded
process and inspects the durable journal after the decision. A valid record
observation advances the journal to version 2 even when the selected key is
then denied; a rejected decision does not authorize signing or a session.

The external Go and Rust adapters call the actual core Gate. The trusted
Source and Clock are synthetic, and the Source asserts validation of its
fixture rather than executing a registry proof or deployment read. The suite
also does not verify an application-message signature or expected-peer
binding. It therefore provides key-choice evidence only, not complete
ID-03, REG-02, or 0.10.0 conformance. Earlier observations keep their
original revision and verdict.

Local bounded execution matched **7/7 cases per core** at Go
`fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`, using the previously
built adapters for those exact revisions. CI rebuilds and runs both adapters
from the pinned source revisions.

Run the unit checks and the bounded core observations with the pinned core
revisions in the [CI job](../.github/workflows/ci.yml). The runner writes
the suite/base hashes, exact request hashes, executable hashes, revisions,
raw responses and per-case verdicts to its JSON report.
