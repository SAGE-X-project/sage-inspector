# Current-spec client result-consumption observations

The [four case fixtures](../vectors/0.10.0/exec-client-consumption.json)
exercise the actual Go and Rust Guard Client APIs through bounded local
adapters. They cover duplicate result consumption, pending after a terminal
result, conflicting terminal results, polling frequency, and expiry. The
input to each adapter excludes the expected answer. The bridge independently
verifies each signed result against the exact intent digest, checks that
successful handoffs retain the original intent, and reads the durable Client
journal. The [archived observations](evidence/current-spec/exec-client/)
include the runner, adapter source, pinned executable hashes, and both
subjects' per-case results.

Both cores match all four fixtures as `PARTIAL`; the other 477 parent cases
are `NOT_RUN` in these selected reports. The tests observe local Client
behavior and inert transport handoffs. They do not establish a model decision
boundary, deployed tool isolation, or complete protocol conformance.
Reassess the archive with
`python3 -B scripts/check_current_spec_exec_client_evidence.py`.
