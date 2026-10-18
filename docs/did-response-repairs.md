# Repaired DID response observations

This separate subject checks the required active `deactivated: false` member
and `sageCode: representation.unsupported` using the original adopted SAGE
0.10.0 DID fixture expectations. It also reruns the other twenty-three native
cases. The three unsupported contracts remain unsupported and the other
555 adopted cases remain unexecuted. Successful cases are PARTIAL observations
of fixture-source library behavior, not full protocol conformance or message
key authority.

The historical `adapters/did-profile`, its dependency pins, observer, fixtures,
known-gap checks and reports are unchanged. In particular, its two failures
remain findings of that historical subject. No expected body is edited to
produce success. The new subject manifest records both exact public module
versions and checksums. The new `adapters/did-response-current` uses the same
bounded observer program with the repaired dependency graph, and its tests
require the two previously absent members instead of accepting the old gaps.

The CI job runs the fresh executable before authored tests. It preserves the
raw output of all twenty-five processes, binary hash before/after execution,
compiler BuildInfo and both dependency identities, module verification and
source hashes, checkout revision/tree and coverage. It then runs vet, race tests
and scenario controls, retaining the existing 90% coverage threshold.

Only in-memory registry records, direct library calls and owned loopback TLS
are used. Deployment, registry authority, actual protected ingress, signing,
replay defense, trust selection and whole-client adoption remain unverified.
Reports from different subjects or from the separate DID standards inventory
must not be added together. This is independent LLM review plus bounded
execution evidence, not an organizationally independent external audit or
compiled-byte attestation.
