# Current-spec durable dispatch observations

The [four independently checked sequences](../vectors/0.10.0/exec04-dispatch.json)
run actual Go and Rust Guard dispatch gates with an inert local effect sink.
They check that a valid signed intent commits its exact tool arguments and
measured instance once. Changing the approved manifest or reaching the
exclusive expiry before dispatch yields zero effects. After a committed
dispatch and process reopen, the same call is `UNKNOWN`; neither core
commits it again. The journal states and a hash of the exact inert effect
are part of each expected result.

The [archived observations](evidence/current-spec/exec04/) pin `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`392cee767e98b1ede02674bc4feab92b2689e726`. Reassess them with
`python3 -B scripts/check_current_spec_exec04_dispatch_evidence.py`.

The selected evidence run contains four runtime observations per core.
All four match as `PARTIAL`; the other 477 parent cases are `NOT_RUN` in this
selected report. This is separate from the cumulative primitive reports.
The local sink does not certify a deployed loader, real external effect,
full parallel-replica coordination, or host capability isolation.
Overall conformance remains `NOT_ESTABLISHED`.
