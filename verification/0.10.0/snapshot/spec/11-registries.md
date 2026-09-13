# 11. Registries

Target: **0.10.0**. These are SAGE-local tables, not IANA assignments.
Requirements: R-1, R-3, R-19, R-29, R-30, R-34, R-35.

The tables this specification maintains, and how an entry is added. A
registry exists so that a new algorithm, label, header, profile or
diagnostic code can be introduced without editing the chapters that use it
(`00-overview.md` §5).

## 1. Registration procedure — TABLE-01 (R-3, R-32, R-34)

1. A proposal is an issue in this repository naming the registry, the value
   requested, the chapter that will use it, and the requirement from
   `charter.md` it serves.
2. An entry is added by a pull request that changes this chapter, the
   chapter that defines the behaviour, and a positive/negative inspector test contract. Executable vectors and
   independent tests are release evidence; existing vectors do not acquire
   validity by changing a version string.
3. Values are assigned in the order accepted. A value is never reused, and
   an entry is never changed in meaning; a superseded entry is marked
   obsolete and stays in the table.
4. Version changes follow `00-overview.md`; pre-1.0 incompatible changes
   require a new explicit wire version and migration notes, never silent fallback.
5. Ranges reserved for private use are marked in each table; values outside
   them are assigned only by the procedure above.

## 2. Signature algorithms — TABLE-02 (R-19, R-29)

Names as they appear in the `alg` parameter of a message signature
(`03-rfc9421.md`) and in a verification method (`10-resolution.md`).

| Name | Key type | Digest | Signature encoding | Chapter | Status |
|---|---|---|---|---|---|
| `ed25519` | Ed25519 | none (pure) | 64 bytes, RFC 8032 | `01-crypto.md` | mandatory |
| `sage-secp256k1-keccak256` | secp256k1 | Keccak-256 | 65 bytes, `r ‖ s ‖ v`, low-S | `01-crypto.md` | optional |
| `ecdsa-p256-sha256` | P-256 | SHA-256 | 64 bytes, `r ‖ s`, low-S | `01-crypto.md` | optional |

`sage-secp256k1-keccak256` is a SAGE-private HTTP signature algorithm,
not JOSE `ES256K` (which uses SHA-256). Implementations MUST NOT alias those
names. Unsupported algorithms fail closed. RSA is not supported in 0.10.0.

Names beginning `x-` are for private use and MUST NOT appear in a record or
a message that leaves a deployment.

## 3. Key types and encodings — TABLE-03 (R-29)

How a public key appears in a registry record and in a resolved document.

| Key type | Use | Wire encoding in a record | Document encoding |
|---|---|---|---|
| Ed25519 | signing | 32 bytes | JSON Web Key, `OKP`, curve `Ed25519` |
| secp256k1 | signing | 65 bytes, uncompressed, `0x04` prefix | JSON Web Key, `EC`, curve `secp256k1` |
| P-256 | signing | 65 bytes, uncompressed, `0x04` prefix | JSON Web Key, `EC`, curve `P-256` |
| X25519 | key agreement | 32 bytes | JSON Web Key, `OKP`, curve `X25519` |

Raw record bytes are serialized as canonical unpadded base64url. JWK
coordinates are likewise unpadded base64url; chapter 10 fixes exact members.

A registry profile MAY accept a subset of these types and MUST reject a key
whose type it cannot verify (`09-registry.md` §4).

## 4. Domain separation labels — TABLE-04 (R-19, R-28, R-34)

Labels are exact ASCII bytes, including punctuation. Chapters defining the
construction specify delimiters and length fields; this table is an index,
not an alternative encoding. Legacy `v1` labels are not 0.10.0 aliases.

| Label | Use | Chapter |
|---|---|---|
| `sage-pop-0.10.0` | signing-key possession/KEM endorsement | `09-registry.md` |
| `sage-claim-0.10.0` | registry claim commitment | `09-registry.md` |
| `sage-card-0.10.0` | SAGE card proof | `07-a2a.md` |
| `sage-execution-intent\|0.10.0`, `sage-tool-result\|0.10.0` | Execution Guard intent/result (followed by NUL) | `../profiles/agent-mcp-security.md` |
| `sage-wire-request\|0.10.0`, `sage-wire-response\|0.10.0` | signed transport domains (followed by LF) | `08-transport.md` |
| `sage-hpke-combiner\|0.10.0`, `sage-hpke-ack\|0.10.0` | handshake derivation and confirmation | `04-hpke.md` |
| `sage-hpke-info\|0.10.0`, `sage-hpke-export\|0.10.0`, `sage-hpke-complete\|0.10.0` | handshake domains (followed by LF where chapter 04 specifies) | `04-hpke.md` |
| `sage-record\|0.10.0` | record AAD | `05-session.md` |
| `sage-session\|0.10.0`, `sage-c2s-key\|0.10.0`, `sage-s2c-key\|0.10.0` | session derivation | `05-session.md` |

Legacy labels `sage-pop-v1`, `sage/hpke-info\|v1`,
`sage/hpke-export\|v1`, `SAGE-HPKE+E2E-Combiner`, the `SAGE-c2s:*`/
`SAGE-s2c:*` labels, `SAGE-cb-v1`, `sage/hpke+e2e v1`,
`sage-session-keys-v1`, `sage-directional-keys-v1`,
`sage-session-rekey-v1` are **obsolete** and reserved against reuse.
Legacy `es256k` Keccak behavior is obsolete; no alias is permitted.

The original-capture commitment also uses `sage-original|0.10.0` followed by NUL and the length-framed input list defined in the Execution Guard profile. This is a commitment domain, not a signature domain.


The policy commitment label `sage-policy|0.10.0` is followed by NUL and JCS(P),
as defined in EXEC-02. It commits a provisioned policy descriptor and is not a
signature domain or a portable authorization token.

## 5. Registry kinds — TABLE-05 (R-2, R-3)

The kind component of an identifier (`06-did-sage.md` §1) names
the kind of registry that holds the record. A kind is added by the
procedure of §1 together with its profile.

| Kind | Locator syntax | Profile |
|---|---|---|
| `eip155` | decimal chain ID then lowercase contract address | `09-registry.md` §6 |
| `solana` | reserved; unsupported in 0.10.0 | `09-registry.md` §7 |
| `web` | a domain name serving the registry document | `09-registry.md` §8 |

## 6. Transport headers — TABLE-06 (R-15, R-34)

| Header | Direction | Meaning | Chapter |
|---|---|---|---|
| `X-SAGE-Version` | request and response | exact `0.10.0`; signed wherever the binding signs headers | `03-rfc9421.md`, `08-transport.md` |
| `X-SAGE-DID` | request and response | the sender's identifier; MUST agree with the `keyid` of the signature | `08-transport.md`, `03-rfc9421.md` |
| `Signature-Input`, `Signature` | request and response | RFC 9421 fields | `03-rfc9421.md` |
| `Content-Digest` | where a body exists | RFC 9530 field | `03-rfc9421.md` |

Headers beginning `X-SAGE-X-` are for private use.

Optional chapter 08 projection headers are `X-SAGE-Message-ID`,
`X-SAGE-Context-ID` and `X-SAGE-Task-ID`. When present they equal the corresponding
verified body member; they never supply unsigned routing or authority.

## 7. Diagnostic codes — TABLE-07 (R-35)

These codes are for logs, conformance reports and resolution errors. An application-message
verifier MUST NOT tell a sender which check failed (`charter.md` R-35); it
returns a single authentication failure and records the code locally.

| Code | Meaning |
|---|---|
| `sig.missing` | no signature field present |
| `sig.malformed` | a signature field could not be parsed |
| `sig.unknown-label` | the requested label is absent |
| `sig.base-mismatch` | the signature base could not be reconstructed |
| `sig.bad` | the signature did not verify |
| `sig.alg-mismatch` | the algorithm does not match the resolved key |
| `sig.stale` | outside the freshness window |
| `sig.replay` | the nonce or sequence has been seen |
| `sig.coverage` | a required component is not covered |
| `sig.binding` | a response is not bound to its request |
| `digest.missing`, `digest.mismatch` | body digest absent or wrong |
| `size.exceeded` | a field or body exceeds its maximum |
| `id.malformed` | the identifier does not parse |
| `id.unknown-kind` | the registry kind is not implemented |
| `record.not-found` | the registry has no record for the identifier |
| `record.inactive` | the record is not active |
| `version.unsupported` | protocol version absent or unsupported |
| `record.stale`, `record.invalid` | stale/rollback state or malformed authoritative record |
| `key.expired` | key expiry reached |
| `record.unreachable` | the registry could not be read |
| `key.not-in-record` | the key identifier names no key in the record |
| `key.unproven` | the record does not carry an accepted proof for the key |
| `key.revoked` | the key is revoked |
| `pop.bad` | a proof of possession did not verify |
| `session.unknown`, `session.replay`, `session.window`, `session.aead` | session record failures |

Resolution errors are reported as problem details (RFC 9457) whose type is
the code above, as `10-resolution.md` §5 defines.
