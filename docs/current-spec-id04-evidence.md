# Current-spec registry lifecycle

ID-04 applies the common registry lifecycle to every registry kind. Four
revision-bound fixtures cover an authorized key addition from an active
record, an unauthorized actor, a proposed DID change during key addition,
and reuse of an existing key name. The positive fixture uses a signing key
from the independently audited registry vectors. The starting record is
projected to active version 2, following the audited created-to-active
transition; a successful addition would produce version 3 and exactly one
mutation. The negative fixtures each change one request field and expect
zero mutations. They are partial probes of the wider lifecycle contract,
which also covers creation, activation, revocation, deactivation, version
compare-and-swap, proofs, and operator authority.

The [preserved 138-case Go/Rust run](evidence/current-spec/id04/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`3b2aa8c3f0d160a5dfeca41db4a16231a9defe88`. Recheck fixtures,
runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_id04_evidence.py`.

Neither primitive adapter exposes `sage.registry.lifecycle.apply`, so all
four ID-04 cases remain `UNSUPPORTED` for each core. A separate bounded
[core capability run](evidence/current-spec/id04/capability/report.json)
sent `mutate` to the Go and Rust registry gates between two journal reads.
Both gates explicitly returned `UNSUPPORTED`; the journal remained at its
initial version. This demonstrates the missing mutation API and no observed
journal change for that unsupported request. It does not establish any
authorized lifecycle transition or deployed registry authority.

Across all 481 cases, Go has 18 `FAIL`, 87 `UNSUPPORTED`, 33 `PARTIAL`, and
343 `NOT_RUN`; Rust has 12 `FAIL`, 86 `UNSUPPORTED`, 40 `PARTIAL`, and 343
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
