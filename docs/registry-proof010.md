# 0.10.0 registry proof byte inspection

Target: `sage-spec` `5ec68684df4e449a3963724444bfba64a70b825f`,
Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, and Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`.

The bounded Inspector adapters call each core's new REG-04 challenge-byte
constructor in a separate local process. They compare both signing-key and
X25519 endorsement outputs against the unchanged
[`sage-spec` fixture](../vectors/0.10.0/registry-proof-0.10.0.json), including
SHA-256, and check three ordinary malformed-input refusals. The local run
produced ten core observations. CI repeats the run against the three exact
source revisions and uploads its raw inputs, outputs, revisions and fixture
hash as a separate artifact.

This is partial evidence for `mllm-pop-exact-bytes` only. The other seven new
Inspector parents remain `NOT_RUN`: a byte constructor cannot verify a PoP
signature, endorse a KEM key with a registered active signer, register a
complete record, or complete a transcript-bound HPKE handshake. Existing
`registry010` trusted-Source gates are not a substitute for that Source's
full record and proof validation. Neither a third-party audit nor 0.10.0
protocol conformance is established. Prior Inspector evidence is unchanged.

Local execution from a checkout with sibling `sage-spec`, `sage` and
`rs-sage-core` directories:

```sh
(cd adapters/go && go test -race ./cmd/registry-proof010 && go build -o /tmp/registry-proof-go ./cmd/registry-proof010)
cargo test --locked --manifest-path adapters/rust/Cargo.toml --bin registry_proof010
cargo build --locked --manifest-path adapters/rust/Cargo.toml --bin registry_proof010
python3 -B scripts/test_registry_proof010.py --spec-root ../sage-spec --go-root ../sage --rust-root ../rs-sage-core --go /tmp/registry-proof-go --rust adapters/rust/target/debug/registry_proof010 --output /tmp/new-registry-proof010-results
```

The output directory must be new and must not be under `docs/evidence`.
