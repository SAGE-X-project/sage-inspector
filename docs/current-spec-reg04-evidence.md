# Current-spec registry proofs and KEM endorsement

REG-04 binds a signing key proof to the registry identifier, agent
identifier, key name, algorithm, and decoded public key bytes. An X25519 KEM
key receives an endorsement from an accepted signing key; it cannot sign
its own proof. A retained endorsement can still be checked using a
historical signer after revocation, but that signer cannot authenticate a
new message or endorse a new key. Proof of possession alone cannot authorize
a registry mutation or controller transfer.

Five [fixed public scenarios](../vectors/0.10.0/reg04-scenarios.json) cover a
valid historical KEM endorsement on read, copying the same proof to another
registry, a proposed controller transfer with unchanged valid proofs, a KEM
claiming to be its own proof signer, and a 31-byte X25519 public key with a
valid endorsement signature. Four controls retain the historical message
and new-endorsement rejections plus a valid/changed-registry signature pair.
The independent checker verifies the public signatures and isolates the
controller, signer-role, and key-length defects.

The [preserved 204-case Go/Rust run](evidence/current-spec/reg04/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`f1623637b0e9776846268ccbbd6ad5b47ff3f4f8`. Reassess fixture,
runner, binary, and observation hashes with
`python3 -B scripts/check_current_spec_reg04_evidence.py`.

Neither current core primitive adapter exposes the complete REG-04 record,
domain-bound proof, or controller-mutation decision; all five bound cases
are `UNSUPPORTED`. The adapters' older `sage.registry.pop.verify` operation
does not consume the current Registry ID field, so its response is not
counted as current-spec proof evidence. A separate
[bounded signature run](evidence/current-spec/reg04/primitives/report.json)
shows both cores accept five isolated Ed25519 signatures and reject the
changed-registry challenge. Accepted signatures include the controller
transfer, KEM self-claim, and invalid-length key scenarios: generic
signature verification cannot decide their Registry policy. KEM private-key
possession remains a handshake property and is not inferred here. Full
REG-04 conformance remains `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 153 `UNSUPPORTED`, 33 `PARTIAL`, and
277 `NOT_RUN`; Rust has 12 `FAIL`, 152 `UNSUPPORTED`, 40 `PARTIAL`, and 277
`NOT_RUN`.
