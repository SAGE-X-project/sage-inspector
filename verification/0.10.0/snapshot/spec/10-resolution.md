# 10. Resolution and the resolved document

Target: **0.10.0**. Requirements: R-4, R-8, R-9, R-14, R-28 to R-30.
Legacy `vectors/did.json` is not current conformance evidence.

## 1. The document — RESOLVE-01 (R-4, R-14, R-29)

The JSON DID document has `id`, `verificationMethod`, `authentication`,
`assertionMethod`, `keyAgreement`, `service`. No `@context` is included:
this is the JSON representation with media type `application/did+json` in
[DID Core](https://www.w3.org/TR/did-core/). Key type is `JsonWebKey2020`.
This projection does not claim JSON-LD processing or fetch remote contexts.
The registry's account/controller representation is management data, not
a fabricated self-controller DID; it remains in SAGE metadata.

| Source | Projection |
|---|---|
| record ID | document `id`, exact canonical DID |
| accepted/unexpired signing key | verification method and references in `authentication`, `assertionMethod` |
| accepted/unexpired X25519 key | verification method and reference in `keyAgreement` |
| revoked/expired key | no verification method; retained in authoritative record |
| created/deactivated record | empty verification methods and relationship arrays |
| registry service | `{ "id": DID + "#" + name, "type": type, "serviceEndpoint": uri }` |

Each verification method has exactly `id` (DID plus immutable key name),
`type`, `controller` (the subject DID), `publicKeyJwk`. Keys and services
are sorted by ASCII name; a service name MUST NOT collide with a key name.

JWKs contain exactly `kty`, `crv`, `x` and, for EC keys, `y`. The types/curves
are chapter 11. `x`/`y` are unpadded canonical base64url, 32 decoded bytes
each; EC coordinates come from the validated uncompressed point. Reject
private `d`, wrong curves, invalid points, extra/contradictory members and
noncanonical encodings. Algorithm is determined from the authenticated
registry entry; accepting a JWK does not authorize arbitrary algorithms.
See [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) and
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).

## 2. Resolving — RESOLVE-02 (R-4, R-8, R-9, R-36)

`resolve(identifier)` returns `didDocument`, `didDocumentMetadata`,
`didResolutionMetadata`. An implementation MUST:

1. Check syntax/size and select an explicitly supported registry kind.
2. Acquire an authorized fresh observation under chapter 09, never follow
   a resolver URL supplied by the unverified sender.
3. Validate complete record structure, ID equality, algorithm encodings,
   proofs, version monotonicity and state from that single observation.
4. Project the validated record and metadata. No missing proof or missing
   state is defaulted to accepted/active.

An arbitrary third-party resolver response over TLS is not a blockchain
proof. A verifier must either validate registry evidence itself or explicitly
trust the resolver's authenticated identity and observation policy. This
trust choice is deployment configuration, not peer-supplied input.
Historical resolution may be provided as a separate administrative API but
MUST NOT authorize present messages or bypass current revocation checks.

## 3. Metadata — RESOLVE-03 (R-4, R-9, R-14)

`didDocumentMetadata` contains `deactivated` (boolean), `versionId` (record
version), and `sage` object with `state`, `controller`, `observedAt`,
`source`, `observedTime`. `observedAt` is the finalized block hash for eip155
or the `issued` integer for web. `source` is the configured source identity
(ASCII string <= 2048 bytes), not evidence by itself; `observedTime` is the
local integer Unix second when observation completed. State is always
explicit, including `created`. No `canonicalId`/`equivalentId` aliases are
emitted. `didResolutionMetadata` contains `contentType` equal to
`application/did+json` on success.

A deactivated/created record resolves successfully for inspection but MUST
NOT authenticate a protected operation. Successful resolution is not a
successful authorization decision. Maximum complete resolution response is
262144 UTF-8 bytes, with at most 128 keys and 16 services inherited from the
record; JCS chapter 02 bounds apply.

## 4. Dereferencing a key — RESOLVE-04 (R-8, R-9)

Dereference only canonical full DID URLs. Resolve afresh, then use exact
ID equality. Absent keys fail with `key.not-in-record`; a retained revoked
or expired record entry can produce `key.revoked` or `key.expired` locally.
No alternate-key search is permitted. Public authentication responses
collapse these details under chapter 08; administrative resolution is not
an authentication oracle for signature validity.

## 5. Errors and HTTP binding — RESOLVE-05 (R-14, R-34, R-35)

Optional read-only binding: authenticated TLS
`GET /0.10.0/identifiers/{identifier}`; path transport percent-encoding is
decoded exactly once and the resulting DID must obey chapter 06 (which
forbids percent-encoding within the DID). Reject queries and extra path
segments. A request MUST include `X-SAGE-Version: 0.10.0`; other versions
are rejected without fallback. Respond with that header and `Cache-Control:
no-store`. Accept `application/did+json` for document only, or
`application/json` for the three-member resolution envelope above. No
unregistered `application/did` or `application/did-resolution` media type is
claimed. An authentication caller needs the metadata and authoritative
record validation, not only the bare document.

Errors use [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html)
`application/problem+json`, with `type` equal to
`https://sage-x-project.github.io/sage-spec/errors/` plus the local code,
`title` a short description and `status` matching HTTP status.

| Code | HTTP status |
|---|---|
| `id.malformed`, `id.unknown-kind`, `version.unsupported` | 400 |
| `record.not-found`, `key.not-in-record` | 404 |
| `record.unreachable`, `record.stale`, `record.invalid` | 502 |
| `size.exceeded` | 413 |

No partial document is returned on failure. These diagnostics describe
public resolution, not the check that failed on a signed application
message. Unauthenticated error bodies never authorize retry with weaker
settings; detailed internal endpoints require deployment access controls.

## 6. Security and evidence

DID Core defines a data model rather than a guarantee that a resolver is
honest or fresh. Source trust, fail-closed observation and record proof
validation address A-2/A-4/A-6 within the declared boundary. Endpoint fetches
remain controlled to prevent SSRF. RFC 7517/8037 encoding rules are adopted;
SAGE intentionally restricts optional JWK members for one wire form.
Independent DID-consumer interoperability and hostile-resolver tests remain
future inspector work, not evidence claimed by this documentation update.
