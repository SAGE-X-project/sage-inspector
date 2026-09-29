# Current-spec execution result observations

The [nine checked fixtures](../vectors/0.10.0/exec-results.json) exercise
exact component-manifest bytes, one wrong artifact hash, signed result
identity and intent binding, exclusive result expiry, invalid proof, and MCP
structured/text agreement. The wrong-issuer and wrong-intent result envelopes
carry valid signatures; the changed-proof envelope does not. The MCP mismatch
changes only the text representation while retaining the signed structured
result.

The [archived Go and Rust observations](evidence/current-spec/exec-results/)
pin `sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`,
Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`d9d7b7f536c72e97d829759428b0eccacd39d1e5`. Reassess them with
`python3 -B scripts/check_current_spec_exec_results_evidence.py`.

Both cores match all nine selected primitive expectations. The selected
report has nine `PARTIAL` and 472 `NOT_RUN` parent cases per core. These
checks do not prove that the manifest pins the loaded instance, that a
terminal result is durably consumed once, or that every protected MCP call
passes through a mandatory trusted gate. Overall conformance remains
`NOT_ESTABLISHED`.
