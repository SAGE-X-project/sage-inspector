# Current-spec registry key encodings

TABLE-03 binds a registry record's raw public key to its projected DID JWK.
The [fixed scenarios](../vectors/0.10.0/table03-scenarios.json) cover a
matching uncompressed secp256k1 key, a compressed record key, a short JWK
coordinate, a correctly typed 32-byte X25519 KEM key, and a 31-byte X25519
record key. Eleven independent controls check Ed25519 and P-256 encodings,
X25519 role and spelling, JWK type and curve, record-to-JWK byte equality,
prefix, canonical base64url, private JWK members, and Ed25519 length.

These fixtures exercise synthetic record-to-JWK encoding. They do not validate
elliptic-curve points, proof of possession or KEM endorsement, a fresh Registry
observation, or interoperability with an independent DID consumer. All five
runtime bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table03/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`9ddb759fbfa2ae867f9ec05f7a7f014f6aa22385`. Reassess 258 runtime
observations per core with
`python3 -B scripts/check_current_spec_table03_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all five key-encoding
operations. Across all 481 cases, Go has 18 `FAIL`, 207 `UNSUPPORTED`, 33
`PARTIAL`, and 223 `NOT_RUN`; Rust has 12 `FAIL`, 206 `UNSUPPORTED`, 40
`PARTIAL`, and 223 `NOT_RUN`. Conformance remains `NOT_ESTABLISHED`.
