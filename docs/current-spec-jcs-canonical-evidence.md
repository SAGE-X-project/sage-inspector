# Current-spec JCS canonical-byte observations

Four independent fixtures check RFC 8785 byte relations: different object
member orders produce identical canonical bytes, array order is preserved,
Unicode strings are not normalized, and `1.0` renders as `1`. These
expectations were fixed before the core run and are grounded in
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), sections 3.1 and 3.2.

Both pinned cores returned the expected bytes for all four fixtures. The
[preserved raw sixteen-case run](evidence/current-spec/jcs-canonical/) also
replays seven JCS-01 and five JCS-02 fixtures. Reassessment with
`python3 -B scripts/check_current_spec_jcs_canonical_evidence.py` yields Go:
four `FAIL`, twelve `PARTIAL`, 465 `NOT_RUN`; Rust: two `FAIL`, fourteen
`PARTIAL`, 465 `NOT_RUN`. No case is fully passed.

These fixtures observe canonicalization output but do not verify that a
receiver reconstructed signing bytes, rejected a changed signature, or bound
the parsed value to execution. They therefore remain partial JCS-03 evidence
and do not establish 0.10.0 conformance.
