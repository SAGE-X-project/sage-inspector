# Current-spec registry identity

ID-02 requires each identifier to name one registry and one local agent,
without aliases or noncanonical spelling. Four revision-bound fixtures
cover equal identifiers in one registry, equal local IDs in different
registries, a forbidden chain-kind alias, and an uppercase chain address.
The authority comparison requests include the full registry identifiers;
the syntax probes each include an independently valid chain DID as control.

The [preserved 128-case Go/Rust run](evidence/current-spec/id02/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`7d560bde61e4750e687a10b2d295a0d3a8760dc9`. Recheck fixture
provenance, runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_id02_evidence.py`.

Neither primitive adapter exposes registry identity comparison, so the
same-registry and different-registry cases are `UNSUPPORTED`. This does not
establish registry namespace uniqueness or cross-registry isolation. Both
cores reject the canonical chain DID and accept the forbidden `eth` alias;
the alias case is `FAIL`. They reject the uppercase address too, but also
reject its canonical control, so the normalization case remains `FAIL`.
These observations cover DID parsing only, not registry state or proof of
possession.

Each core has two ID-02 `FAIL` cases and two `UNSUPPORTED` cases. Across all
481 cases, Go has 18 `FAIL`, 77 `UNSUPPORTED`, 33 `PARTIAL`, and 353
`NOT_RUN`; Rust has 12 `FAIL`, 76 `UNSUPPORTED`, 40 `PARTIAL`, and 353
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
