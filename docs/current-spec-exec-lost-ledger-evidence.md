# Current-spec missing Guard ledger observations

The [two current case fixtures](../vectors/0.10.0/exec-lost-ledger.json)
first dispatch one exact signed intent to an inert local sink and retain its
durable ledger. The runner then makes that ledger unavailable and asks the
actual Go or Rust Guard adapter to reopen it. Both adapters reject the
attempt, emit no further result or effect, leave the saved history unchanged,
and do not recreate the missing ledger.

The [archived observations](evidence/current-spec/exec-lost-ledger/) pin the
specification, runner, subject revisions and executable hashes. Both cases
are `PARTIAL` for both cores; the other 479 parent cases are `NOT_RUN` in
these selected reports. This proves only local fail-closed behavior after
ledger loss. It does not verify the trusted epoch-recovery procedure,
distributed reconciliation, or deployed tool isolation. Reassess with
`python3 -B scripts/check_current_spec_exec_lost_ledger_evidence.py`.
