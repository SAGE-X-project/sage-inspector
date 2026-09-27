# Current-spec HPKE completion verification

HPKE-04 closes the completion payload to exactly `v`, `task`, `transcript`,
`ackTagB64`, and `sigB64`. The complete initiation must be echoed in the
transcript. The responder signs the specified domain prefix and canonical
unsigned completion with its selected Ed25519 key. The initiator also checks
the authenticated outer response, the pending request, the exact ACK tag,
and current bound keys before creating a session.

Five revision-bound fixtures cover selected boundaries. The positive case
independently checks canonical completion fields, exact initiation echo,
the RFC 5869 ACK calculation, and the inner signing bytes, then submits that
signature to each core. One denial changes only the `kid` field in the
signed completion, leaving its signature and ACK unchanged. Another uses a
validly signed but wrong ACK. A third presents a valid completion to a
different pending request. The last sends an invalid inner signature to the
core signature verifier. The changed `kid` case may fail both the signature
and ACK checks; it does not isolate which check fires.

The signature primitive cannot prove the authenticated outer response,
current key selection, constant-time ACK comparison, pending-state cleanup,
or zero session and protected-dispatch effects. Neither current core adapter
exposes the complete `sage.hpke.complete.verify` boundary, so its three
denial cases remain `UNSUPPORTED`. All fixtures use deterministic local test
values and do not send network traffic.

The preserved Go/Rust observations are checked by
`python3 -B scripts/check_current_spec_hpke04_evidence.py`.
