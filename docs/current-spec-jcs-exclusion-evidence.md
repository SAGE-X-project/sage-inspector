# Current-spec proof exclusion boundary

JCS-04 requires the exact owning signature member to be excluded from JCS
bytes. The four Inspector fixtures cover a valid SAGE Agent Card, removal of
`proof.verificationMethod`, removal of the `proof` object, and alteration of
the authenticated `proof.alg`. The valid control's card signature is checked
independently with OpenSSL over `sage-card-0.10.0`, a NUL byte, and the JCS
card with only `proof.proofValue` removed. The three candidate cards differ
from that control only at the stated path.

The [preserved twenty-case Go/Rust run](evidence/current-spec/jcs-exclusion/)
records `UNSUPPORTED` for all four JCS-04 cases in both subjects. Their current
Inspector adapters do not expose the 0.10.0 `sage.card.verify` operation;
this observation does not prove whether underlying core source code can
verify the card. Recheck the fixture relationships and raw results with
`python3 -B scripts/check_current_spec_jcs_exclusion_evidence.py`.

Across all twenty current JCS fixtures, Go has four `FAIL`, four `UNSUPPORTED`,
twelve `PARTIAL`, and 461 `NOT_RUN`; Rust has two `FAIL`, four `UNSUPPORTED`,
fourteen `PARTIAL`, and 461 `NOT_RUN`. No case is fully passed and overall
conformance remains `NOT_ESTABLISHED`. The next adapter work needs a direct
card-verification entry point that observes schema, current Registry Source
binding, exact signing bytes, and the absence of protected effects on rejection.
