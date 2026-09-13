# 9. The registry and the agent lifecycle

Target: **0.10.0**. Requirements: charter R-3 to R-13, R-28 to R-30.
Existing `vectors/registry.json` and `vectors/did.json` are historical
fixtures. This chapter defines the abstract contract; contract ABI,
transaction encoding and deployment addresses belong to deployment bindings.
No existing deployment is certified by this document.

## 1. The record — REG-01 (R-4, R-6, R-28, R-30)

A record is JSON with exactly these members. Strings/arrays are bounded
before cryptographic work. The complete encoded record is at most 65536
UTF-8 bytes and follows chapter 02.

| Member | Value |
|---|---|
| `id` | canonical DID, chapter 06 |
| `controller` | ASCII authorization identifier, 1–256 bytes; deployment binding defines its authenticated meaning |
| `keys` | 1–128 entries including tombstones, sorted by ASCII `name` |
| `services` | 0–16 objects with exactly `name`, `type`, `uri`; sorted by `name` |
| `state` | `created`, `active`, `deactivated` |
| `version` | decimal string, 1 through 18446744073709551615, no leading zero |

A key has exactly `name`, `alg`, `key`, `proof`, `state`, and optionally
`expires`. Name is chapter 06 `key-id`; algorithm is chapter 11; `key` is
unpadded canonical base64url of chapter 11 raw bytes; state is `accepted`
or `revoked`. Optional expiry is integer Unix seconds, 0 through
9007199254740991; it is unusable when `now >= expires`. Names and key bytes
MUST NOT be reused within a record, including revoked keys. Key material,
algorithm, proof and expiry are immutable after addition. Duplicate names,
unknown members, unknown algorithms and private key material are rejected.

Each service name uses `key-id`, is unique, type is 1–64 ASCII bytes, and
Service names MUST NOT collide with any key name.
URI is an absolute HTTPS URL of at most 2048 ASCII bytes without userinfo
or fragment. An endpoint is discovery metadata, not an authorization grant.
A deployment may restrict endpoints further but MUST NOT fetch URLs merely
to validate a record. Cards bind this array without a second key store.

## 2. What a verifier reads — REG-02 (R-7, R-8, R-12)

For signatures the exact named accepted, unexpired key MUST be used, never
trial verification over alternatives. An `active` record must have at least
one usable signing key. For a new handshake choose the accepted, unexpired
`x25519` key whose name sorts first in ASCII order; the handshake MUST name
that full key URL and bind it to its transcript. Rotation in flight cannot
silently substitute another key. A record without an eligible KEM key
cannot establish a session; signed-message verification can still work.

## 3. Operations and lifecycle — REG-03 (R-3, R-5, R-7, R-10, R-11)

```text
absent -> created -> active -> deactivated
              \-------------> deactivated
```

Creation starts at version `1`; each successful atomic mutation increments
version exactly once. Mutations require the authenticated controller or
explicitly delegated operator and the expected previous version. Wrong
version, unauthorized or invalid mutation fails without changing anything.
A version at its maximum permits no further mutation; deployments MUST
arrange deactivation before exhaustion. The limit is not permission to wrap.

| Operation | Atomic rule |
|---|---|
| create | reserve unused identifier and bind controller, initial keys and services; check all proofs; a client chooses the identifier before forming proofs; creation needs at least one unexpired accepted signing key |
| activate | `created` to `active`, with at least one unexpired accepted signing key |
| add key | active only; new immutable name/material and valid proof; at most 128 lifetime entries |
| revoke key | accepted to revoked, retained forever; if no usable signing key would remain, deactivate atomically instead |
| update services | replace the complete bounded services array, active only |
| authorize/revoke operator | explicit controller-authorized scoped delegation; operators cannot change controller or delegate further |
| deactivate | created or active to deactivated; terminal, record remains readable |

The identifier is never reassigned, and revoked keys never become accepted
again. Controller transfer/recovery is not defined in 0.10.0: use a new
record and explicit peer configuration. Operators are management-plane data
whose authenticated enforcement is required by the deployment binding, not
DID signing keys. Expiry can leave a record active but unusable; verifiers
reject it until a still-authorized controller adds a new proven key.

## 4. Proof of possession and KEM endorsement — REG-04 (R-5, R-6, R-12, R-29)

```text
challenge = ASCII("sage-pop-0.10.0")
          || len16(registry-id) || registry-id
          || len16(agent-id) || agent-id
          || len16(name) || name
          || len16(alg) || alg
          || len16(keyBytes) || keyBytes
```

Here `len16(x)` is the unsigned two-byte big-endian byte length (not the
field itself); text fields are canonical ASCII and `keyBytes` is decoded
public key material. The key name prevents rebinding a captured proof to a
new key entry. A signing entry's `proof` is exactly `{ "signer": full-key-URL,
"value": unpadded-base64url-signature }`; signer MUST equal its own key URL.
Sign the challenge with the algorithm of chapter 01; the registry and
resolver both check it. There is no separate SHA-256 exception for
secp256k1. A proof is at most 87 encoded signature characters.

An X25519 entry has the same proof shape but its signer names an accepted,
unexpired signing key in the same proposed/current record. Signing keys
are validated first. This proves **controller-authorized endorsement of the
KEM key, not possession of its private key**. Actual KEM possession is
confirmed by the authenticated handshake. On later reads an endorsement
may be verified with its retained historical signer even if that signer
is now revoked/expired; that signer is not thereby usable for messages.
A deployment can revoke the endorsed key separately if compromise requires
it. The registry's authenticated mutation supplies authorization; a PoP
alone MUST NOT authorize create/update or a controller substitution.

## 5. Observation and revocation — REG-05 (R-9, R-13)

Every protected-message decision, session operation and execution decision
MUST obtain a fresh authoritative observation of all keys/records it relies
on. No earlier `accepted`/`active` result may authorize a later operation.
A single operation may share one consistent snapshot, acquired after that
operation starts and at most 5 seconds before its final authorization gate;
if it expires while waiting, re-resolve. Missing/untrusted clock, timeout,
stale state, version rollback or conflicting state MUST fail closed.

Observation is a linearization point, not a promise to foresee future
revocation. No already completed side effect is undone. Registry publication
or chain finality latency precedes observation; a verifier adds no grace
period. An arbitrary remote RPC provider's assertion of "latest" is not
proof of freshness. Deployments MUST configure a trusted authoritative
source (self-validated node or explicitly trusted resolver), its identity,
chain/network binding and readiness policy. If readiness cannot be
established, return `record.unreachable`. A malicious trusted registry or
validator remains outside the stated trust boundary.

Confirmed monotonic tombstones may be cached permanently. Unfinalized
revocation observations may only be used to deny the current operation;
they MUST NOT become irreversible tombstones. Persist the highest observed
finalized version per registry/record, reject rollback (`record.stale`), and
re-establish source readiness after restart. For blockchain profiles the
observation is one finalized block hash: no mixture of latest state and
finalized keys. Publication-to-finality delay and observed latency MUST be
reported in deployment measurements, not represented as zero.

## 6. Profile: eip155 — REG-06 (R-2, R-3, R-5, R-11, R-13)

Locator has two segments: a positive decimal chain ID without leading zeros
(at most 32 digits), then `0x` and exactly 40 lowercase hex digits of the
registry address. Agent ID is 1–64 ASCII letters, digits, `.`, `_`, `-`,
excluding `.` and `..`. Controller is a lowercase account address on that
chain. Registry algorithms MUST include Ed25519; unsupported optional
algorithms are rejected, not stored as accepted without proof verification.

A deployment binding MUST pin chain ID, registry address, deployed code hash
and upgrade policy, authenticated read/write ABI mapping to sections 1–5,
operator scopes, transaction authorization, finalized-node readiness checks,
and measured costs/latency. Absence of any of these prevents a conformance
claim for that deployment; it does not invite clients to guess an ABI.

A claim uses commitment then reveal. Compute SHA-256 over
`ASCII("sage-claim-0.10.0") || 0x00 || JCS(claim)` where claim has exactly
`registryId`, `agentId`, `controller`, `keys`, `services`, and `salt` (32
random bytes in canonical unpadded base64url). The commitment is submitted
by the authenticated controller, scoped to its account and this registry;
a reveal by another account cannot consume it. Reveal must be after the
commit block, within 256 blocks, and match all fields. Consuming it and
creating the record are atomic; duplicates fail. The commitment does not
promise a human-chosen name cannot independently be claimed by someone
else. Activation is a separate authenticated operation after creation.

## 7. Profile: solana — REG-07 (R-2, R-3)

`solana` is reserved, not an executable 0.10.0 profile. The previous draft
claimed ordering made front-running protection unnecessary without defining
an authorization or atomic claim construction. No such guarantee is made.
A conforming 0.10.0 resolver returns `id.unknown-kind`; a future profile must
define a full deployment binding and pass independent inspector cases.
The abstract registry model remains chain-independent.

## 8. Profile: web — REG-08 (R-2, R-3, R-4, R-9, R-11)

This optional non-blockchain profile is not equivalent to prior on-chain
registration assurance. Its trust root is the configured HTTPS origin and
its operator. A deployment requiring blockchain registration MUST reject
web identities rather than silently fall back to them.

Locator is a lowercase ASCII DNS name, maximum 64 bytes, with labels of
1–63 alphanumeric/hyphen characters, no leading/trailing hyphen, no trailing
dot, no IP literal or port. Internationalized names must be configured in
ASCII A-label form. Agent ID follows section 6. Read exactly
`https://<domain>/.well-known/sage/agents/<agent-id>` over authenticated TLS;
redirects, HTTP downgrade, intermediated positive-cache responses, `304`
and non-200 responses fail resolution. Fetch MUST use `Cache-Control:
no-cache, no-store`; the origin MUST return `Cache-Control: no-store` and
freshly produce the record. Response is an object with exactly `record`,
`issued`, `expires`; record is section 1 and timestamps are integer Unix
seconds. Require `issued <= now < expires`, `expires-issued <= 5` and
positive lifetime. Maximum response is 69632 bytes.

The domain authority controls creation and writes; it MUST authenticate the
controller/operator, enforce section 3 atomically and retain tombstones.
Administrative API is deployment-specific and never inferred from a card.
No hidden-claim guarantee is offered. Self-signing a substituted key set
adds no independent protection against a malicious origin and is not a
substitute for TLS origin trust. A record response is consumed for one
operation only and section 5 still applies. Implementations must explicitly
allowlist registry origins and network destinations before fetch to avoid
SSRF; deny inaccessible or unapproved origins, never follow card endpoints.

## 9. Security and verification status

A-4/A-5 are addressed through authenticated writes and signing-key PoP;
A-6 through explicit authoritative observation and no positive-cache reuse.
DID registration does not attest a program's integrity or user intent.
The protected Client/component boundary is defined in the integration
profile. Signature-key compromise in that protected boundary remains an
assumption, not something registry lookup repairs.

[RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) supplies HTTP cache
semantics; SAGE's one-operation policy is stricter. Independent contract
review, malicious-resolver/reorg testing and measured revocation latency
remain inspector/deployment work. No such tests were run for this revision.
