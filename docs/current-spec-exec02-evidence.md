# Current-spec execution commitments

The [four fixtures](../vectors/0.10.0/exec02-primitives.json) test the exact
framing of a captured original request, one-byte alteration of that request,
the approved policy descriptor commitment, and one policy artifact digest
change. Expected SHA-256 digests are computed independently from the domain
separators and encoded bytes. The two changed-input cases compare both control
and candidate digests; they do not claim that a receiver rejected an
unauthorized call.

The [archived Go and Rust runs](evidence/current-spec/exec02/) pin `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`6b56a3a425af6e5440f61da21d3e2920696bb174`. Reassess the 275 runtime
observations per core with
`python3 -B scripts/check_current_spec_exec02_evidence.py`.

Both cores matched the four primitive expectations. Go now has 18 `FAIL`,
220 `UNSUPPORTED`, 37 `PARTIAL`, and 206 `NOT_RUN` parent cases; Rust has
12 `FAIL`, 219 `UNSUPPORTED`, 44 `PARTIAL`, and 206 `NOT_RUN`. The four EXEC-02
cases remain `PARTIAL`: trusted capture before expansion, exact-call policy
authorization, receiver mapping, retirement ordering, and independent
downstream authorization were not observed. Overall conformance remains
`NOT_ESTABLISHED`.
