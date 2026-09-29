# Current-spec Agent Card freshness

CARD-03 requires the signed card to be current against a freshly resolved,
authoritative registry record. Five bound fixtures cover a valid card, the
exact expiry second, a newer registry record version, a deactivated Agent,
and a changed registry service endpoint. The negative registry cases retain
the exact signed card and alter only one trusted test-context field. This
separates a card-to-registry mismatch from a signature failure. The source
card is independently signed and verified in the registry fixture audit.

The [preserved 154-case Go/Rust run](evidence/current-spec/card03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`abecbc3895a721ec70afa20168eca13309f7851f`. Reassess its fixture,
runner, executable, and observation hashes with
`python3 -B scripts/check_current_spec_card03_evidence.py`.

Neither core primitive adapter exposes `sage.card.verify`; all five CARD-03
cases are `UNSUPPORTED`. The fixture context models the resolved record, but
this run does not perform authoritative chain resolution, freshness checks,
or card-to-record comparison. It does not establish full CARD-03 conformance.

Across all 481 cases, Go has 18 `FAIL`, 103 `UNSUPPORTED`, 33 `PARTIAL`, and
327 `NOT_RUN`; Rust has 12 `FAIL`, 102 `UNSUPPORTED`, 40 `PARTIAL`, and 327
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
