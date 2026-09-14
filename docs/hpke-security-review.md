# HPKE composition and compromise review

This is a local design analysis accompanying the Inspector's fixed vectors, not a
formal proof or external cryptographic audit. It evaluates the frozen SAGE0.10.0
composition. The construction is not changed to match either legacy core.

## Model and assumptions

The network adversary can read, replay, reorder, substitute and interleave messages,
choose its own keys, and corrupt selected secrets at the times listed below. Honest
endpoints initially use current authenticated signing/KEM key bindings and enforce
both transport signatures, complete-request response binding and the HPKE completion
signature. Their protocol verifier and private state remain within a trusted
execution boundary until the specified compromise. Registry trust and the mandatory
Client execution boundary are separate requirements; DID registration alone is not
runtime integrity or detection of signing-key misuse.

Assumptions include X25519 computational hardness, secure HKDF/HMAC and signatures,
independent fresh HPKE/C/S ephemeral contributions, and effective disposal of secrets.
Deterministic fixture values test calculations; they provide no evidence of entropy,
independence in production, constant-time execution or physical memory erasure.
Both Python and Node use cryptographic backends: two calculation paths do not amount
to independent expert approval.

## Composition and authentication

The pinned suite's Base exporter is a building block. Sender identity must come
from authenticated protocol envelopes, as required by SAGE. The HPKE suite identifier
includes the selected AEAD even though this profile uses the exporter rather than
HPKE ciphertext. [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1)
describes the context schedule; the fixed Appendix A.2.1 exporter answers validate
that schedule in this inspection.

SAGE binds identities, selected key URLs, context, version, suite, combiner and nonce
through B/info/exportCtx. The complete initiation and responder contribution/handle
enter T/th. The response signature and exact outer request binding must authenticate
that same pending initiation. Every echoed field is compared, including fields that
are also hashed or signed. The fixed tests include correctly re-signed altered echoes;
signature validity cannot replace this equality check.

The seed uses both exporterHPKE and ssE2E with transcript-dependent extraction and
expansion. This supplies explicit input and domain binding; it is not by itself a
proof of a robust two-source combiner under correlated or adversarial inputs. RFC5869
[extract and expand](https://www.rfc-editor.org/rfc/rfc5869.html#section-2) define the
primitive argument meanings. SAGE's composition still needs analysis under its actual
corruption and transcript model. In particular, knowledge of one component must not
be casually described as proof that the other component always supplies security.

ACK validates possession of the combined secret at completion. The initiator may
establish only after echoed fields, current keys, response signatures and ACK all
pass. The responder has no completed initiator key confirmation at RESPONSE_SENT;
its first valid authenticated session record supplies that confirmation. No protected
execution or application send is allowed before the required transition. The present
six scenarios focus on initiator completion, invalidation and deadlines; responder
AEAD/replay atomicity belongs to the session inspection work.

## Compromise timing

| Adversary knowledge | Consequence under the stated assumptions |
|---|---|
| Public transcript only | Does not directly reveal either DH secret or the seed; public sid/kid are identifiers, not capabilities. |
| Responder static KEM private key learned after completion and ephemeral erasure | Recorded enc permits recovery of the HPKE exporter. The intended protection of the past seed then depends on the erased C/S ephemeral exchange and the combiner assumptions; this is not an HPKE-only forward-secrecy guarantee. |
| Initiator HPKE encapsulation private key only | Permits deriving the exporter from public recipient key and bound domains. Extra C/S secret must still remain unknown for the intended separation to help. |
| C or S ephemeral private key only | Permits deriving ssE2E from the other public contribution. It does not alone disclose the HPKE exporter under the initial assumptions. |
| Static KEM key plus either C or S private key | Both inputs can be reconstructed from the recorded transcript; the past seed is recoverable. |
| Initiator pending state, including HPKE ephemeral and C private keys | Both inputs can be reconstructed once the completion's public S is known. No protection against this full state compromise is claimed. |
| Responder state holding KEM and S private material | Both inputs are available. Registered identity and public transcript hashing do not restore secrecy. |
| Retained session seed | The fixed session schedule permits deriving all its generations and directions. It is not a forward-secure ratchet or post-compromise recovery mechanism. |
| Selected signing key compromised during establishment | An attacker may authenticate substituted material under an apparently active identity. Current-key lookup alone cannot detect misuse of an unrevoked key; containment/revocation and a new handshake are required. |

These are conditional deductions from the inputs and trust model, not experimentally
measured resistance to endpoint compromise. The later-static-key case is an intended
property requiring additional assurance; test-vector agreement is insufficient to
approve it as a proved protocol guarantee.

## Substitution, interleaving and rejection

Unknown-key-share and role substitution require agreement on identities and selected
keys, not merely equal seed bytes. The B/T binding and strict pending echo checks are
the intended defenses. The role-swapped positive schedule demonstrates changed
transcript-derived material; negative echoes and a different valid pending request
exercise rejection. They do not quantify over all concurrent sessions or model every
adaptive key-compromise trace.

Null X25519 outputs must be rejected both by the HPKE KEM and by the direct exchange.
The Rust raw DH helper currently returns zero for tested low-order inputs, while its
higher-level handshake checks zero separately. That primitive finding is not proof
of a handshake bypass. Both existing combiners also accept invalid component lengths
at the selected helper boundary and use historical expansion labels. The report
separates these observations from the unsupported complete 0.10.0 path.

Invalid completion closes/discards pending state and creates no session. Retry after
that destruction cannot revive it. Absolute initiation expiry and 300 monotonic
seconds are independently tested at equality. A retransmission must not extend either
deadline. The fixture state model audits expected logical counters; actual erasure,
concurrency and effect instrumentation remain requirements on future core bindings.

## Assurance still required

A formal or independently reviewed agreement/secrecy model should cover concurrent
sessions, unknown-key-share, signing/KEM corruption at multiple times, reused entropy,
registry changes and active transcript manipulation. Deployment tests must establish
entropy sources, erasure, constant-time comparisons and the trusted verifier boundary.
Those assurance activities remain explicit follow-ups. They do not block preparing
spec-based Inspector cases, and completing this inspection implementation does not
close them or certify the entire protocol.
