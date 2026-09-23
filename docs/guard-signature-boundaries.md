# Guard signature primitive boundaries

This suite calls the existing Go and Rust intent/result verification APIs through
thin primitive adapters. It is separate from the unadopted MCP setup profile and its
historical 71-case catalog. No handshake, owner implementation, dispatch, network or
tool effect runs here; historical lifecycle 37 NOT_RUN and conformance NOT_ESTABLISHED
remain. Current per-case results are tracked separately in the runtime evidence overlay.

Ten public fixtures cover two roles (intent and completed result), each with a normal
Ed25519 proof, corrupted Ed25519 proof, inactive Ed25519 key, valid P-256 proof, and a
P-256 proof labelled Ed25519. Each actual core should accept only the normal Ed25519
control: ten processes per core, twenty total. The trusted test Authority supplies
public fixture material and fixed time/policy, not live registry observations.

Fixtures were signed with Python cryptography. Node/OpenSSL independently reconstructs
the signed bytes, matches the public key to adapter input, and verifies signatures
before either core runs: eight cryptographically valid and two invalid. An inactive
key and a mislabelled algorithm can be cryptographically valid while failing protocol
acceptance. P-256 signatures use the baseline's fixed-width r/s representation.

The existing Authority interfaces are Ed25519-only. A P-256 public key cannot represent
an active P-256 registry entry through those interfaces. Rejection therefore proves
fail-closed behavior of the current primitive API for those inputs, not that the
future complete MCP binding discriminates every supported registry algorithm or
rejects at a particular internal stage. Secp256k1, transport/handshake roles and fresh
registry validation remain outside this suite. Do not mark the proposal's corresponding
cryptographic scenarios PASS from these narrower results.

```sh
python3 -B scripts/test_guard_signature_boundaries.py
python3 -B scripts/check_guard_signature_boundaries.py \
  --go /path/to/go-adapter --rust /path/to/rust-adapter \
  --go-root /path/to/pinned-sage --rust-root /path/to/pinned-rs-sage-core \
  --output /tmp/new-signature-report
```

Build adapters from the pinned revisions used by the existing record CI. The checker
requires those source revisions without tracked edits, records binary hashes and saves
each exact request/stdout/stderr. An adapter crash, unsupported verdict or wrong response
identity fails; none counts as rejection. CI retains a separate signature-boundary
artifact. Existing reports cannot be overwritten. Supplied binary hashes identify
executables; they are not an attestation that arbitrary caller-supplied binaries came
from the supplied source. CI's build steps establish that association for its run.

## Canonical suite and historical correction

The original result-role P-256 fixtures contain high-S signatures. They are
mathematically valid ECDSA proofs but do not meet the local SAGE low-S rule. The
original report therefore establishes rejection of those inputs, not rejection of
fully profile-valid P-256 result proofs. Its frozen bytes and results are retained.
Use `guard-canonical-signatures.json` for the corrected algorithm-boundary evidence.
All four P-256 signatures in that suite satisfy the low-S requirement; original
messages and keys are unchanged. This corrects test evidence, not a core vulnerability.

The canonical suite adds four secp256k1 fixtures: intent/result, each correctly labelled
or labelled Ed25519. Python/OpenSSL signs the Keccak-256 digest with prehashed ECDSA
(the prehashed API does not rehash it with SHA-256). Low-S normalization is applied
only while producing public test fixtures; incoming signatures are never normalized
by the auditor. A Go/decred auditor independently verifies scalar bounds, ordinary
ECDSA and recovery to the exact key for v=0/1, using Keccak without an EIP-191 prefix.
The auditor imports no SAGE verification code. Node/OpenSSL separately verifies the
Ed25519/P-256 fixtures and, for the canonical suite, their scalar bounds and low-S.

Run the checker with `--canonical --secp-auditor /path/to/audit-guard-secp` in addition
to the existing arguments. Build that auditor from `adapters/go/cmd/audit-guard-secp`.
Fourteen cases per core mean 28 actual primitive processes; each accepts only the two
Ed25519 positive controls. The report records which suite ran and the auditor hash.
CI keeps `guard-canonical-signatures-<revision>` separately from the historical suite.

Both unsupported elliptic-curve families still reach an Ed25519-only Authority seam;
this does not establish active-key registry negotiation or complete MCP binding
conformance. Separate pinned core tests now establish the intent and correlated-result
algorithm boundaries for the case overlay. Outer and handshake roles remain NOT_RUN,
while the historical 71-case source catalog is unchanged.


## Rechecking canonical evidence

`scripts/verify_guard_signature_evidence.py` checks all 28 canonical exchanges against
the pinned fixtures and core revisions. It requires the expected Inspector revision
and the original trusted Go/Rust adapter and secp auditor binaries via `--revision`,
`--go`, `--rust`, and `--audit`; `--evidence` selects the report directory. It reruns
the independent signature audit and compares executable hashes with the report.
The binaries must come from a trusted build, not from an untrusted evidence archive.
Cross-platform rebuilds need not produce the same executable hash.

The checker rejects missing, extra or symlinked files, altered requests, incorrect
responses, duplicate JSON members, nonempty stderr, changed response digests,
missing/duplicate/reordered results, mismatched revisions and conformance promotion.
CI invokes it directly on the real runtime output before artifact upload. Four unit
tests also exercise synthetic evidence and negative controls; their fixtures are
not recorded as actual core execution.

This is a consistency check, not cryptographic attestation of who produced a report,
when a process ran, or which source built a binary. Report hashes alone cannot prove
those facts. The historical MCP catalog remains 71 NOT_RUN, current case results are reported
by the separate overlay, historical lifecycle cases remain 37 NOT_RUN, and conformance
remains NOT_ESTABLISHED.
