# Current-spec registry value governance

TABLE-01 defines how SAGE-local registered values are assigned and preserved.
The [fixed scenarios](../vectors/0.10.0/table01-scenarios.json) cover selected
unchanged signature algorithm meanings and a domain label, reuse of the
obsolete `sage-pop-v1` label, a silent change to the `ed25519` digest, and an
`x-` private signature name on an external wire. Eight supplemental controls
check the synthetic proposal's issue fields, the registry and behaviour
chapters, positive/negative Inspector contracts, assignment order, explicit
pre-1.0 version change, migration notes, local private use, and refusal of
an unassigned public value.

Each case has partial runtime and `document_review` bindings. The
[source review](evidence/current-spec/table01/source-review.json) pins the
registry and version-policy chapters, but no accepted registration issue,
pull request, release, or deployment artifact was supplied for review. The
synthetic proposal is a procedure test, not an assignment or a promised
release number. All document-review tracks remain `NOT_RUN`.

The [preserved Go/Rust run](evidence/current-spec/table01/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`b256d8335e420596c37c2befdae6f9c635638ad9`. Reassess 250 runtime
observations per core with
`python3 -B scripts/check_current_spec_table01_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all four value
admission operations. Full TABLE-01 conformance remains `NOT_ESTABLISHED`.
Across all 481 cases, Go has 18 `FAIL`, 199 `UNSUPPORTED`, 33 `PARTIAL`, and
231 `NOT_RUN`; Rust has 12 `FAIL`, 198 `UNSUPPORTED`, 40 `PARTIAL`, and 231
`NOT_RUN`.
