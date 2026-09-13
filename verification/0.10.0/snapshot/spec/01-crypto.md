# 1. Cryptographic primitives

Status: normative design for SAGE `0.10.0`. Requirement references are to
[the charter](../charter.md). Existing `vectors/crypto.json` and Go
`pkg/agent/crypto/keys/` are historical implementation evidence, not proof
that these revised requirements are implemented.

## 1. Key types and algorithm selection

**CRYPTO-01 (R-8, R-19, R-29).** Every implementation MUST support Ed25519.
The other signing suites below are optional; an unsupported suite MUST fail
closed without substituting another algorithm. A signing `kid` MUST name an
explicit active proven key in the resolved sender record. X25519 MUST NOT
be used for signatures. Registry type integers are registry-specific and
MUST NOT be interpreted as a wire algorithm identifier.

| Key | Wire public key | Signature | Wire algorithm |
|---|---|---|---|
| Ed25519 | 32 bytes | 64-byte R followed by S | `ed25519` |
| secp256k1 | 65-byte uncompressed SEC1, `04` followed by X and Y | 65-byte r, s, v | `sage-secp256k1-keccak256` |
| P-256 | 65-byte uncompressed SEC1 | 64-byte r followed by s | `ecdsa-p256-sha256` |
| X25519 | 32 bytes | none | HPKE KEM only |

Coordinates, r and s are fixed-width 32-byte unsigned big-endian integers.
The secp256k1 identifier is a SAGE-local identifier, not an IANA assignment
or JOSE ES256K. Compressed keys, DER signatures, extra bytes and legacy RSA
signatures MUST be rejected in this version. This resolves the historical
RSA-PSS identifier/PKCS#1 v1.5 operation mismatch by excluding RSA entirely.

## 2. Signing and verification

**CRYPTO-02 (R-19, R-29).** Ed25519 uses the pure RFC 8032 operation over
exact message bytes, without prehash or context. Verifiers MUST reject
noncanonical encodings, S outside the scalar range, invalid points, and
small-order public keys or R points. For deterministic cross-library acceptance, decoded A and R MUST be nonidentity members of the prime-order subgroup ([L]A and [L]R are identity, L as in RFC 8032). Require the uncofactored equation [S]B = R + [k]A, with k = SHA-512(R_encoding || A_encoding || message) reduced modulo L. Mixed-torsion points are rejected even if a cofactored verifier would accept. This is the stricter SAGE verification profile. P-256 hashes message bytes with
SHA-256; secp256k1 hashes them with Keccak-256, without EIP-191 prefix.
Neither SHA3-256 nor SHA-256 substitutes for Keccak on that suite.
ECDSA signatures MUST have `1 <= r < n` and `1 <= s <= floor(n/2)`;
verifiers MUST reject high-S rather than normalize attacker input.
secp256k1 v MUST be 0 or 1, and recovery using v MUST produce the resolved
public key in addition to ordinary ECDSA verification. Point validation
includes curve membership and rejection of infinity.

**CRYPTO-03 (R-19).** ECDSA signers SHOULD use RFC 6979 deterministic
nonces. Secure randomized signing is permitted: identical signatures from
two signers are not a conformance requirement. After low-S normalization,
secp256k1 signers MUST adjust v to retain the correct recovered key.
Verification is deterministic even when signing is randomized.

## 3. Key references, secret handling and domain separation

**CRYPTO-04 (R-8, R-15, R-29).** The historical
`hex(SHA-256(pub)[0:8])` identifier MAY appear in logs, but MUST NOT select
or authenticate a key. Protocol key references use the full DID key URL
specified in [chapter 06](06-did-sage.md). JSON binary values use canonical
unpadded base64url except where a chapter explicitly requires standard
base64. Public key bytes MUST match the resolved key exactly.

**CRYPTO-05 (R-19, R-22).** CSPRNG-generated secrets and ephemeral keys
MUST be fresh. Private keys, shared secrets and expired traffic keys MUST
remain inside the trusted implementation boundary and MUST NOT be logged.
Comparisons of secret-derived authentication values MUST use a
constant-time equality operation. A signing API MUST apply the domain
prefix specified by its calling chapter; it MUST NOT expose arbitrary
signing authority to untrusted plugins. Signature validity establishes
provenance, not safe meaning or user approval.

Registration proof-of-possession has its own explicitly specified signing
input in chapter 06; the historical SHA-256 registration challenge is not
a reason to change the messaging suite or accept multiple digests.

## 4. References and verification status

[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) supplies Ed25519;
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) supplies an optional
deterministic ECDSA nonce procedure. P-256 HTTP signatures use
[RFC 9421 §3.3.4](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.4).
The stricter encoding acceptance, low-S rule and secp256k1 name above are
SAGE design decisions. Independent Go/Rust verification, malformed-point
cases and new signature-encoding vectors remain inspector follow-up work.
