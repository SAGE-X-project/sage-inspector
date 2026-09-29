# Current-spec guarded dispatch denials

The [three case fixtures](../vectors/0.10.0/exec-denials.json) submit one
unchanged signed intent to the actual Go and Rust Guard dispatch APIs. An
explicit policy denial, unavailable active signing key, and retirement before
dispatch each produce a rejection, an empty durable ledger, and zero inert
tool effects. The independent case checker locks the changed control and
excludes the expected answer from the adapter input.

The [archived observations](evidence/current-spec/exec-denials/) pin the
specification, subject, runner and executable hashes. Both cores match all
three selected fixtures as `PARTIAL`; the other 478 parent cases remain
`NOT_RUN` in these reports. The observations do not establish a distributed
resolver outage, atomic retirement under a live concurrent effect, or host
isolation. Reassess them with
`python3 -B scripts/check_current_spec_exec_denial_evidence.py`.
