# Current-spec registry lifecycle

REG-03 requires an authenticated controller or scoped operator, an exact
expected version, one version increment per accepted mutation, and no state
change on rejection. Deactivation is terminal; version exhaustion cannot
wrap to zero.

Five [fixed public scenarios](../vectors/0.10.0/reg03-scenarios.json) derive
from the independently authored Registry mutation sequence: authorized
created-to-active transition, stale expected version, a second compare-and-
swap request after another request committed the same starting version,
reactivation after deactivation, and an unauthorized actor. The second
request represents the losing side of concurrent mutation; it does not
simulate scheduling or prove linearizability. Two controls cover the maximum
version and valid active-to-deactivated transition. A separate checker
validates the source sequence, public key proofs, expected state, and zero
mutation effects on each rejected attempt.

The [preserved 199-case Go/Rust run](evidence/current-spec/reg03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`dfd2613d9d1ec897a6619d26498e70dba9ae8457`. Reassess hashes,
observations, and case statuses with
`python3 -B scripts/check_current_spec_reg03_evidence.py`.

Neither current primitive adapter exposes `sage.registry.lifecycle.apply`;
all five bound cases are `UNSUPPORTED`. A separate bounded
[core gate run](evidence/current-spec/reg03/capability/report.json) reused
the established Registry capability runner with the same pinned core
revisions. Both local gates returned `UNSUPPORTED` for `mutate`, and their
local journals were unchanged between inspection calls. This is a limited
runtime observation of the missing mutation API, not a successful
authorization, atomic commit, or deployed registry test. REG-03 conformance
remains `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 148 `UNSUPPORTED`, 33 `PARTIAL`, and
282 `NOT_RUN`; Rust has 12 `FAIL`, 147 `UNSUPPORTED`, 40 `PARTIAL`, and 282
`NOT_RUN`.
