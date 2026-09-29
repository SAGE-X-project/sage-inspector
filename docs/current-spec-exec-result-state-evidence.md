# Current-spec signed result lifecycle observations

The [three lifecycle fixtures](../vectors/0.10.0/exec-result-state.json)
run actual Go and Rust Guard result programs with an inert local sink and
durable journal. A pending snapshot is signed before completion, a second
response to that invocation is refused, and a later retrieval returns the
stored signed terminal result. A rejecting invocation after dispatch cannot
replace the eventual completion. A terminal result remains stored after its
exclusive expiry, but late retrieval is denied. The independent bridge
verifies each observed result signature and its exact intent digest and
compares a published terminal to the durable stored envelope.

The [archived observations](evidence/current-spec/exec-result-state/) pin
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`445fc8dd9a4dea452be866c220b9ed75c2f710fd`. Reassess them with
`python3 -B scripts/check_current_spec_exec_result_state_evidence.py`.

All three cases are `PARTIAL` for both cores; the other 478 parent cases
are `NOT_RUN` in this selected report. This checks executor result storage
and local publication. It does not establish final Client output consumption,
external tool effects, or deployment-wide consistency. Overall conformance
remains `NOT_ESTABLISHED`.
