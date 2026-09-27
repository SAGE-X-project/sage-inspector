# Current-spec HPKE suite and key roles

HPKE-01 fixes one suite: Base mode, X25519/HKDF-SHA256 KEM `0x0020`,
HKDF-SHA256 KDF `0x0001`, and ChaCha20-Poly1305 AEAD `0x0003`.
The protocol uses the HPKE exporter, and the authenticated envelopes must
establish current Ed25519 signing keys while a distinct active X25519 key
is selected for the responder KEM. HPKE Base does not authenticate the sender.

Four revision-bound Inspector fixtures cover the rule. The positive case
binds RFC 9180 Appendix A.2.1's fixed Base exporter answer to the current
Go and Rust core APIs. The independent Node HPKE audit recalculates the
published anchor and the SAGE schedule. The remaining cases use a canonical
initiation from the existing 0.10.0 derivation fixtures, then isolate an
unsupported suite, a missing sender envelope signature, and a revoked
responder KEM key. Their trusted context keeps Ed25519 signing keys separate
from the responder's X25519 KEM key. The expected denial includes zero
session creation and protected dispatch; these effects are not yet observed.

The exporter operation proves only a fixed cryptographic primitive result.
It does not prove the envelope authentication, current key resolution,
suite-selection policy, fresh context, or complete session establishment.
Neither current core adapter exposes the scoped `sage.hpke.establish`
operation. Those three denial cases must remain `UNSUPPORTED` until an
authenticated handshake entry point and effect instrumentation are bound.
The fixtures contain only public deterministic test material and run locally;
they do not send network traffic.
