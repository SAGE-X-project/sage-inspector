# Current-spec JCS parser observations

The pinned `sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`
requires JCS-01 to reject duplicate keys, a UTF-8 BOM, unpaired surrogates,
invalid JSON numbers, and negative-zero numeric tokens before canonicalization.
Inspector fixes six independent rejection expectations in its repository-owned
fixtures. The runner sent only their raw input bytes to the pinned Go and Rust
core adapters; the adapters did not receive the expected verdict.

| Case | Input | Go `sage` | Rust `rs-sage-core` |
| --- | --- | --- | --- |
| JCS-01-N01 | Duplicate key | FAIL: accepted last value | PARTIAL: rejected |
| JCS-01-N02 | UTF-8 BOM | PARTIAL: rejected | PARTIAL: rejected |
| JCS-01-N03 | Lone surrogate | FAIL: accepted replacement character | PARTIAL: rejected |
| JCS-01-N04 | Literal `NaN` | PARTIAL: rejected | PARTIAL: rejected |
| JCS-01-N05 | Negative zero | FAIL: accepted as zero | FAIL: accepted as zero |
| JCS-01-N06 | Negative underflow | FAIL: accepted as zero | FAIL: accepted as zero |

The [preserved raw observations and assessed reports](evidence/current-spec/jcs-parser/)
pin the spec revision, Inspector runner revision, fixture hashes, core source
revisions, and executable hashes. Run
`python3 -B scripts/check_current_spec_jcs_parser_evidence.py` to recheck
observation hashes, runner identity, and all 481 assessed statuses. The Go
report has four `FAIL`, two `PARTIAL`, and 475 `NOT_RUN` cases. The Rust report
has two `FAIL`, four `PARTIAL`, and 475 `NOT_RUN` cases. Both retain overall
`NOT_ESTABLISHED` conformance.

These are primitive parser observations. The bridge does not inspect the
receiving chapter's schema or protected dispatch effects. A matching rejection
is therefore `PARTIAL`, never full JCS-01 conformance. Literal `NaN` is an
invalid JSON token, so that fixture observes syntax rejection rather than an
in-memory non-finite value. No core source was edited for this run.
