# Current-spec Agent Card schema

CARD-01 defines a closed, bounded SAGE Agent Card tied to current registry
services. Six revision-bound fixtures cover a valid card, an unknown field,
changed services, a key reference absent from the record, a 65,537-byte card,
and a wrong schema version. Five inputs come from the independently audited
registry/Card vectors. The size case appends only legal JSON whitespace to
the valid signed card, preserving its parsed object and signature while
crossing the 65,536-byte input limit. The valid card's Ed25519 signature is
also independently checked with OpenSSL against the prescribed JCS bytes.
The negative source cards carry updated proof values where their signed
fields change; their schema or registry-binding condition remains the
specified rejection reason.

The [preserved 144-case Go/Rust run](evidence/current-spec/card01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`54876ce421d1c5b8c74ee789ca52c7dac408f313`. Recheck the source
relations, signature, runner hashes, observations, and assessment with
`python3 -B scripts/check_current_spec_card01_evidence.py`.

Neither primitive adapter exposes `sage.card.verify`, so all six CARD-01
cases remain `UNSUPPORTED` in both cores. Reference-vector auditing and
OpenSSL signature verification do not establish a core's card schema,
registry resolution, or protected discovery behavior.

Across all 481 cases, Go has 18 `FAIL`, 93 `UNSUPPORTED`, 33 `PARTIAL`, and
337 `NOT_RUN`; Rust has 12 `FAIL`, 92 `UNSUPPORTED`, 40 `PARTIAL`, and 337
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
