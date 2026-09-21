# Guard signature primitive boundaries

This suite calls the existing Go and Rust intent/result verification APIs through
thin primitive adapters. It is separate from the unadopted MCP setup profile and its
71 NOT_RUN cases. No handshake, owner implementation, dispatch, network or tool effect
runs here; historical lifecycle 37 NOT_RUN and conformance NOT_ESTABLISHED remain.

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
