# Current 0.10.0 specification inventory

Inspector now pins `sage-spec` revision
`dcdd028b5160de5e32eb1f43cf1f71eed3fc4744` in
[`reconciled-spec`](../verification/0.10.0/reconciled-spec/manifest.json).
It contains 45 requirements, 91 rule groups, 489 parent cases and 26
mandatory subscenarios. All 489 parents and 26 children remain `NOT_RUN`
against this exact revision; implementation conformance is `NOT_ESTABLISHED`.

The [earlier 489-case inventory](latest-spec-inventory.md) is preserved at
`44df132fee5925182018ce089dc82435cb353f8a`. The case graph is unchanged.
Among the source files named by that graph, only `spec/09-registry.md` changed:
the web Registry now requires exactly one parameter-free `application/json`
response `Content-Type`, rejects any `Content-Encoding`, and rejects those
fields in trailers. This resolves the prior `REG-08-N04` ambiguity. The
source and vector checks compare exact bytes against the current spec checkout;
neither the earlier excluded case nor its Go/Rust observations is silently
promoted to a result for this revision.

The [13 bounded media subconditions](../vectors/0.10.0/reconciled-spec/reg08-media.json)
cover two accepted media headers and eleven rejection conditions under
`REG-08-P` and `REG-08-N04`. The reference checker validates their source and
expected decisions. A separate runtime observer builds the pinned Go core at
`1dc22e71673bfa40cc63b342a2e66fdfee2f3ee2` and Rust core at
`79fe9bbcd7a417a523d77a267c8420cf4f506746`, runs each case against
both executables, and records the actual verdicts, source revisions and binary
hashes. Inspector also pins the Rust dependency resolution in
[`registry-media-Cargo.lock`](../verification/0.10.0/reconciled-spec/registry-media-Cargo.lock)
because the Rust library does not track a lockfile. Each core matched all 13
media decisions in the local run. The CI report retains the same bounded
evidence for its own build.

The [20 bounded envelope subconditions](../vectors/0.10.0/reconciled-spec/reg08-envelope.json)
now exercise the 69632-byte response limit, closed JSON wrapper, duplicate
members, Unicode and number parsing, and the five-second issued/expires
lifetime. Inspector builds Go core revision
`628d36cce452762abb0c9e4a0e10b35d4a059529` and Rust core revision
`7658959e34f69ad100d085a0a04702dab8d8c2e4` with the pinned Rust
dependency lock. Each matched all 20 expected decisions in a local runtime
check; CI preserves its own per-case report and executable hashes. Accepted
envelopes in these fixtures deliberately contain an empty `record` object.
They do not imply that a usable Registry record exists.

The 13 media observations cover only the response media decision. Neither executable
fetches an HTTP response, verifies TLS or web-origin authority, parses a
complete Registry record, or establishes `REG-08-P` or `REG-08-N04`. Both
parent cases and the remaining 487 parent cases remain `NOT_RUN`; complete
implementation conformance remains `NOT_ESTABLISHED`.
The envelope observations have the same limit: they do not check the nested
record's separate 65536-byte bound, schema, DID, key proofs, or authority.

The [26 bounded record-shape subconditions](../vectors/0.10.0/reconciled-spec/reg08-record-shape.json)
now check the exact encoded 65536-byte record bound, closed fields, web DID
binding, key and service structure, and version. Inspector builds the pinned
Go core at `19c39080cc78918a307bc9008834874558bdd4c8` and Rust core at
`d13b4dff709a90428da4272ce45c1b1df48914b3`, then records each actual
decision and executable hash. Both matched 26/26 cases in the local runtime
check; CI preserves its own report. The positive fixtures use placeholder public
bytes and proof values solely for structural checks. A shape acceptance is
not a valid signature, trusted HTTPS origin, authenticated controller, or
complete Registry observation. All REG-08 parent cases remain `NOT_RUN` and
conformance remains `NOT_ESTABLISHED`.

The [16 bounded proof subconditions](../vectors/0.10.0/reconciled-spec/reg08-record-proofs.json)
exercise REG-04 signatures over the exact web Registry challenge for Ed25519,
P-256, and secp256k1, plus X25519 KEM endorsement. Inspector builds Go core
`3c09b4a497f4086e11ac5fa529ea933df32d7208` and Rust core
`061c2e489e3f388bcee113382167285e17b72064`. The fixed input includes
independently generated Ed25519, X25519, and P-256 material; every actual
decision and executable hash is retained. The Rust build uses the pinned
[`registry-proofs-Cargo.lock`](../verification/0.10.0/reconciled-spec/registry-proofs-Cargo.lock).
Both cores matched 16/16 expected decisions in the local runtime check; CI
preserves its own report. A successful proof check establishes
only these cryptographic subconditions. In particular, a revoked or expired
historical KEM signer still needs authenticated evidence that it was authorized
when the endorsement was added. HTTPS origin, controller and mutation history,
all REG-08 parent cases, and complete conformance remain `NOT_RUN` or
`NOT_ESTABLISHED` as appropriate.

Run the revision-bound checks against the exact spec checkout:

```sh
python3 -B scripts/test_reconciled_spec_catalog.py
python3 -B scripts/test_reconciled_spec_reg08_media.py
python3 -B scripts/reconciled_spec_catalog.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-spec-inventory.json
python3 -B scripts/reconciled_spec_reg08_media.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-reg08-media.json
python3 -B scripts/test_observe_reconciled_reg08_media.py
python3 -B scripts/observe_reconciled_reg08_media.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-media.json
python3 -B scripts/test_observe_reconciled_reg08_envelope.py
python3 -B scripts/observe_reconciled_reg08_envelope.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-envelope.json
python3 -B scripts/test_observe_reconciled_reg08_record_shape.py
python3 -B scripts/observe_reconciled_reg08_record_shape.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-record-shape.json
python3 -B scripts/test_observe_reconciled_reg08_record_proofs.py
python3 -B scripts/observe_reconciled_reg08_record_proofs.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-proofs.json
```

Next, extend the core adapters to authenticate controller and mutation history,
including retained KEM endorsers, and the trusted web origin. Run those paths
against isolated local HTTP/TLS fixtures and retain actual observations.
Only then can Inspector assess `REG-08-P` and `REG-08-N04` as complete cases.
The older 481-case and 489-case evidence directories remain historical.
