# Canonicalization and signature verification evidence

Protocol0.10.0; 47 independent cases in `vectors/0.10.0/jcs-signatures.json`.
The existing26 primitive vectors and pinned386-case planning inventory are unchanged.
This suite reuses the extensible schema1 primitive tooling profile. It adds
`jcs.canonicalize` and `signature.verify`; the Inspector reference returns
UNSUPPORTED for them. Real core adapters perform all subject operations.

## Independent expectations

- Seven positive JCS literals cover recursive sorting, preserved array order,
  UTF-16 ordering, no Unicode normalization, numeric rounding/exponent boundaries
  and positive underflow. Nine negatives apply the stricter SAGE input rules.
  Node's ECMAScript serialization independently confirms the positive literals.
- Ed25519 includes RFC8032 section7.1 TEST1 and mutations of message, signature
  length, scalar bounds and point encodings. Four constructed identity/torsion
  cases satisfy the uncofactored verification equation but violate the explicit
  SAGE prime-subgroup rule. Independent affine integer arithmetic confirms both
  facts; no SAGE code computes their expected verdicts.
- P-256 and secp256k1 use public test-only d=k=1 arithmetic to compute fixed valid
  signatures. OpenSSL verifies the resulting signatures over independently fixed
  SHA-256/Keccak digests. Negatives cover high-S, zero components, DER, key encoding,
  off-curve points, signature length and secp256k1 recovery parity/range.
  Fixed nonces are public fixture construction, never a production signing recipe.

`generate_crypto_vectors.py` regenerates bytes using Python integer arithmetic and
Python cryptography/OpenSSL, with no imports or calls to the inspected implementations.
The Ed25519 public bytes were checked against the downloaded RFC text. The Keccak
empty digest uses the published keccak-hash constant; no SHA3 substitution is made.
[Provenance](evidence/jcs-signatures-provenance.json) records RFC download hashes and
oracle tool versions. This is independently sourced/computed evidence, not an
independent human audit or proof of exhaustive coverage.

Sources: [RFC8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1),
[RFC8785](https://www.rfc-editor.org/rfc/rfc8785.html),
[Keccak empty digest constant](https://docs.rs/keccak-hash/latest/src/keccak_hash/lib.rs.html),
and the pinned SAGE CRYPTO-02/JCS-01/JCS-03 rules.

## Actual subject observations

| Subject | PASS | FAIL | UNSUPPORTED | Overall |
|---|---:|---:|---:|---|
| Go sage c7709b7486e0da94336edc0931fddd87f6a45343 |27|18|2|FAIL|
| Rust206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 |31|16|0|FAIL|

[Go report](evidence/jcs-signatures-go.json),
[Rust report](evidence/jcs-signatures-rust.json).
The same source revisions and hashes from [the source lock](evidence/core-source-lock.json)
apply. Reports identify rebuilt adapter binaries. New Go adapter dependencies are
pinned in its own go.mod/go.sum; Rust uses its existing Cargo.lock.

Both cores accept the equation-valid identity/mixed-torsion Ed25519 cases, negative
zero/negative underflow, high-S ECDSA, DER signatures, missing secp256k1 recovery byte,
wrong recovery parity and recovery value2. Go additionally accepts duplicate JSON
members, lone surrogates and recovery value27. Rust accepts compressed ECDSA keys.
These are observed mismatches with the strict0.10.0 profile, not general claims
that every use of these core libraries is exploitable.

Go's ECDSA API takes affine coordinates. The adapter supports only the uncompressed
65-byte representation it can map without implementing a decoder; the two compressed
key cases are UNSUPPORTED. It does not pre-reject them to manufacture conformance.
Invalid affine points are passed to the core's point validator. Ed25519 raw keys
and raw signatures are passed unchanged. Rust uses core PublicKey::from_bytes,
Signature::from_bytes and Verifier; permissive parsing is therefore visible.

## Operation contract

`jcs.canonicalize`: input `document_hex`; ACCEPT output `canonical_hex` containing
exact UTF-8 bytes. The adapter never normalizes the input document before the core.
`signature.verify`: input `algorithm`, `public_key_hex`, `message_hex`,
`signature_hex`; ACCEPT output `valid:true`; REJECT output `{}`.
Algorithms are ed25519, ecdsa-p256-sha256 and sage-secp256k1-keccak256.
Unmapped algorithms/representations yield UNSUPPORTED; core parse/verification errors
are REJECT. Malformed hex or adapter envelope errors are execution failures, not
cryptographic rejections. Expectations remain exclusively in Inspector.

## Reproduce and interpret

```sh
python3 scripts/generate_crypto_vectors.py /tmp/jcs-signatures.json
cmp /tmp/jcs-signatures.json vectors/0.10.0/jcs-signatures.json
node scripts/check_jcs_literals.js vectors/0.10.0/jcs-signatures.json
```

The generator requires Python cryptography (version recorded in provenance).
Build the adapters using the commands in [core-adapters.md](core-adapters.md), then
run sage-conformance with `-suite vectors/0.10.0/jcs-signatures.json` and an explicit
adapter, subject and revision. Both current subjects deliberately return exit1
because the report contains actual mismatches. Do not change expectations to match
those observations. Scope covers primitive checks, not DID authorization, field
exclusion paths, application integer schemas, full wire parsing or host isolation.

JCS vectors partially exercise JCS-01/03 and signature vectors CRYPTO-02. They do
not mark entire rules or all386 planned scenarios as executed. INS-03's vector
expansion and adapter observations are complete; full field mutation coverage and
state/wire profile checks belong to subsequent work. Findings should be fixed in
core repositories separately and rerun against these frozen expectations.
