# Current-spec provisional responder state

HPKE-05 keeps the responder in `RESPONSE_SENT` after emitting completion. It
must not send application data or execute a protected operation before the
first fully authenticated initiator record. The first accepted record may
have a sequence other than zero and establishes the session atomically with
replay reservation. The pending deadline is exclusive: equality at 300
monotonic seconds or either envelope expiry closes the state. Retransmitted
initiation cannot replace an existing session. Restart discards sessions.

Five revision-bound fixtures cover selected prerequisites and decisions. The
positive case submits the existing sequence-7 first record to each core's
0.10.0 record opener and checks its plaintext. Four denial cases require
zero protected effects before confirmation, closure at the exact pending
deadline, rejection of an initiation with an accepted nonce while a session
exists, and rejection of session reuse after restart. They are tied to the
independently audited stateful session scenarios and the canonical initiation
fixture. All material is deterministic and local.

Opening a record proves only its bounded encryption prerequisite. It does
not prove the signed envelope, current keys, replay reservation, atomic
confirmation, authorization ordering, or session erasure. The current
primitive adapters do not expose the full `sage.hpke.provisional.verify`
stateful boundary. The four denial cases must remain `UNSUPPORTED` until a
version-matched subject adapter and effect instrumentation are available.
The independent session audit checks fixture expectations, not core behavior.

The preserved Go/Rust observations are checked by
`python3 -B scripts/check_current_spec_hpke05_evidence.py`.
