# 2. JSON canonicalisation

Status: normative design for SAGE `0.10.0`.
Historical evidence: `vectors/jcs.json` and `pkg/agent/crypto/jcs/jcs.go`.
Requirements: [R-20, R-28 to R-30](../charter.md).

## 1. Parsing before canonicalisation

**JCS-01 (R-28, R-30).** Signed JSON MUST be UTF-8 without a BOM. Parsers
MUST reject duplicate member names after JSON escape decoding, invalid
UTF-8, unpaired UTF-16 surrogates, invalid JSON numbers, NaN/infinity and
trailing non-whitespace data. Negative-zero numeric tokens (including
`-0.0` and negative underflow to zero) MUST be rejected before canonicalization. The top-level value MUST match the receiving
chapter's schema. Validation MUST occur before a parser loses duplicate
members or replaces malformed text. Object depth is at most 64 (root
container depth 1); input is at most 16 MiB. A more specific chapter limit
also applies. Unknown members in protocol structures MUST be rejected
unless an explicitly defined extension container permits them.

**JCS-02 (R-28).** Protocol integers MUST be exactly representable integers
in `[-9007199254740991, 9007199254740991]`; narrower field ranges apply.
Identifiers, large counters and exact decimal application quantities use
schema-defined strings. A producer MUST NOT silently round an out-of-range
integer into a signed value. Arbitrary application JSON uses finite IEEE
754 binary64 values; applications needing greater precision MUST agree on
string encodings before signing.

## 2. Canonical bytes

**JCS-03 (R-20, R-28).** Implementations MUST use RFC 8785 JCS: recursive
object sorting by UTF-16 code units, ECMAScript number/string serialization,
no insignificant whitespace, and UTF-8 output. Unicode normalization MUST
NOT occur. Array order is preserved. Verifiers MUST reconstruct canonical
bytes from the validated object themselves. Signers and execution code
MUST consume the same parsed values; a later parser with different number
or duplicate-name behavior MUST NOT reinterpret authenticated content.

| Structure | Remove before JCS | Additional signing domain |
|---|---|---|
| Transport request or response | top-level `signature` only | chapter 08 |
| HPKE response | top-level `sigB64` only | chapter 04 |
| Agent Card | nested `proof.proofValue` only | chapter 07 |

**JCS-04 (R-20, R-28).** Removal MUST be limited to the exact member path named by the owning
schema; other members with the same name remain covered. An absent required signature/proof is rejection, not an
empty signature. Other signed structures MUST specify their own exclusion
and domain rules. HTTP signature bases and binary session records MUST NOT
be JCS transformed. HTTP Content-Digest covers received content bytes,
including whitespace, rather than a canonicalized body.

## 3. Security and migration

These restrictions prevent parser disagreement and ambiguous signing inputs;
they do not establish that signed instructions are safe. The old statement
that integers above 2^53 simply lose precision is removed as unsafe protocol
advice. Existing RFC example vectors remain useful algorithm tests but do
not cover the stricter schema, duplicate-member and execution binding rules.

The underlying algorithm is
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), especially its
input constraints and UTF-16 property ordering. Schema restrictions and
resource bounds above are the SAGE profile, not changes to JCS.

Errata review (2026-09-13): [RFC 8785 errata](https://www.rfc-editor.org/errata/rfc8785)
7920 is verified and its negative-zero concern is addressed by JCS-01;
6292 corrects an ECMAScript section reference and changes no wire bytes.
