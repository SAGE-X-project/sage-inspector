# Structured Field serialization and exact URI preservation

The two core verifiers now serialize the admitted Signature-Input component
list before constructing the signature base. RFC 8941 SP at list edges,
between components and after parameter semicolons is accepted, and explicit
`req=?1` becomes `req`. Received parameter order and quoted string contents
remain intact. Signature and Content-Digest retain their canonical profile
requirements; duplicate/unknown parameters and extra dictionary labels fail.

The parser is deliberately bounded: noncanonical integers, escaped string
values, other item types and general Structured Fields are not implemented.
This work does not establish full RFC 9421 or whole SAGE conformance.

## Evidence

Reviewed core revisions used by CI:

| Core | Revision |
| --- | --- |
| Go | `80a07b84b9feb739f1a1af8447c92bb55b56baef` |
| Rust | `cc99efe519eed4574437d23b9843d7bddddc0de5` |

- 34 independently authored Structured Field vectors and 17 URI vectors are
  identical across both cores and Inspector. Core unit tests check admission
  and exact canonical serialization.
- 204 actual CLI process scenarios cover all four Go/Rust combinations.
  Valid cases complete a handshake and deliver the first encrypted record;
  invalid cases assert no replay reservation or established session.
- The request parameter-order case deliberately re-signs after emission:
  the responder accepts it, but the original sender rejects the response
  because it retained a different exact Signature field. Independent checking
  verifies the responder's signature against the altered request. This is a
  request-context rejection, not a parameter-order interoperability failure.
- Five independent helper tests verify the published RFC Ed25519 signature,
  reject base changes and parameter-order changes, and check fixture helpers.
- Existing HTTP session and real loopback TLS regressions remain in CI.
  These new cases use bounded local processes; no network malformed-input
  tests or attack-capable reproduction programs are introduced.

URI tests preserve encoded slash octets and their case, plus versus encoded
space, repeated query names, query order and empty query markers. IPv6 and
nondefault ports are covered. The configured endpoint must already be in the
admitted form; routing compares exact bytes rather than decoding or sorting.

Each runtime report records core revisions, executable/fixture hashes, raw
control log hash and scenario outcomes. Positive base hashes reflect the
independent signer's expected canonical bytes. CI retains an eleventh report
under `http-serialization010`. Prior archived FAIL/UNSUPPORTED/NOT_RUN findings
remain unchanged and conformance remains NOT_ESTABLISHED.

## Reference provenance

The profile vectors are independently authored algorithm-derived cases, not
verbatim RFC examples. Their source sections are [RFC 8941 serialization and
parsing](https://www.rfc-editor.org/rfc/rfc8941.html#section-4) and
[RFC 9421 signature parameters](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3).
A separate fixture preserves the published base, public key and signature from
[RFC 9421 B.2.6](https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.2.6)
and B.1.4. It verifies exact base bytes with Node crypto, independently of
both core implementations. Its coverage is not the SAGE profile.

The user-designated local `rfc9421` reference was consulted at HEAD
`bb17b8b87a09e642ca19ff8a909b1ed6e478a7f6`. Consulted bytes:

| File | SHA-256 |
| --- | --- |
| en.txt | bd168c908b3f436a9e63d7dae6341c933ca01bc628e91ad0770bd8e21e521097 |
| pkg/rfc9421/builder.go | 4022373222055876e515987c89ac8c31c5b481021abebbceddf984472ea19b86 |

The local builder sorts maps and uses a different signature-base structure,
so it remains comparison material rather than the correctness oracle.
Official RFC algorithms and SAGE chapter 03 govern these checks.

## Remaining work

General Structured Field item/string/integer handling and broader endpoint
normalization remain explicitly unsupported. The next transport work is a
WebSocket binding contract and safe runtime verification, followed by durable
replay/quarantine, deployment registry Source and host enforcement evidence.
