# Current-spec execution replay observations

The [four bounded sequences](../vectors/0.10.0/exec05-replay.json) use
actual Go and Rust durable Guard gates with an inert local sink. A separately
signed envelope that changes the nonce while retaining the call ID is
rejected after the first dispatch. An exact duplicate returns the existing
execution state without a second effect. A changed proof is rejected. After
process reopen, repeated delivery returns `UNKNOWN` without dispatch.
Both signatures in the changed-nonce case are independently verified, so
that rejection is not explained by invalid cryptography.

The [archived observations](evidence/current-spec/exec05/) pin `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`12ea75a80f24e55ab8c7c01ac3d53a7e5a600ec2`. Reassess them with
`python3 -B scripts/check_current_spec_exec05_replay_evidence.py`.

The selected run contains four `PARTIAL` cases and 477 `NOT_RUN` parent cases
per core. It observes local identity retention and journal recovery only;
parallel replicas, actual external effects, cancellation, and protected
Client policy remain outside this evidence. Overall conformance remains
`NOT_ESTABLISHED`.
