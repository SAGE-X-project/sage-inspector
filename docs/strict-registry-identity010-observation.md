# Canonical Registry Gate identity observation

The [eight-case suite](../vectors/0.10.0/strict-registry-identity010.json)
checks the 0.10.0 identity admission boundary in both cores. Its source is
`sage-spec` revision `fa006fd917ad365eb554a27f4178301cd66e2379`,
ID-01, ID-02 and the key-reference parsing step of ID-03. The expected
verdicts and durable journal versions are fixed in Inspector, independent of
the Go and Rust implementations.

The test builds existing Registry Gate adapters against Go
`fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`. A separate Rust Cargo
manifest keeps the historical adapter lock file unchanged. Each case runs in
its own bounded process with a synthetic trusted Source, Clock and journal.
After the decision, Inspector reads the journal: a malformed identity or key
URL must be rejected before any positive version is persisted. A canonical
exact signer must be selected and persist the observed version.

Local execution matched **8/8 cases per core**. CI repeats the execution
against exact merged revisions and preserves the report, executable hashes
and raw bounded observations. The Gate tests additionally count Clock and
Source calls to check that malformed input is denied before either is used.

This is an internal admission observation. It does not establish a deployed
Registry Source, full proof validation, expected-peer binding for every
transport, signature verification, or complete ID-03 conformance. Those
parent cases remain `NOT_ESTABLISHED` until integrated execution.
