# 0. Overview

Status: normative design for **0.10.0**, updated from the existing chapters.
Implementation and security proof remain follow-up work.

## 1. Scope

SAGE gives software agents a way to prove who they are and to exchange
messages protected against forgery, replay and disclosure under the charter assumptions. This
specification fixes everything that crosses an implementation boundary.
`charter.md` states the problem, the deployment models, the adversary and
the numbered requirements; every normative statement here serves one of
them and cites it.

| Part | Chapters |
|---|---|
| Primitives: keys, signatures, canonical JSON | `01-crypto.md`, `02-jcs.md` |
| Identity: naming, registration, resolution | `06-did-sage.md`, `09-registry.md`, `10-resolution.md`, `07-a2a.md` |
| Messaging: signed requests and responses | `03-rfc9421.md` |
| Confidentiality: handshake and session records | `04-hpke.md`, `05-session.md` |
| Carriage: envelope and headers | `08-transport.md` |
| Tables and their registration procedure | `11-registries.md` |
| Protected Agent/MCP execution | [Execution Guard](../profiles/agent-mcp-security.md) |

Out of scope, as `charter.md` §1 records: the implementation of any
registry, including the contracts published by
[sage-contracts](https://github.com/SAGE-X-project/sage-contracts); concrete proxy/client implementations and key-storage mechanisms; payment, reputation and staking signals. Required security integration outcomes ARE specified in the Execution Guard profile.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL in this specification
are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when,
and only when, they appear in capitals.

**OVERVIEW-01 (R-1, R-28, R-32).** Grammars are ABNF (RFC 5234) where present. Grammar and prose semantic constraints both apply; satisfying grammar alone does not waive bounds or checks. A contradiction is a specification defect, not permission to choose the weaker rule. MiB means 2^20 bytes and KiB means 2^10 bytes.

Terminology:

| Term | Meaning |
|---|---|
| Agent | A party that holds keys and sends or receives protected messages |
| Controller | The party authorised to change an agent's registry record |
| Registry | The service that holds records binding identifiers to keys |
| Profile | The part of this specification that says how one kind of registry meets the model of `09-registry.md` |
| Resolver | Software that reads a registry and returns a document (`10-resolution.md`) |
| Verifier | The party that decides whether a message is authentic and fresh |
| Initiator, responder | The agent that starts a handshake, and the one that answers |

Encodings:

| Term | Meaning |
|---|---|
| `hex` | lower-case hexadecimal, no prefix |
| `base64` | RFC 4648 standard alphabet with padding |
| `base64url-raw` | RFC 4648 URL-safe alphabet, no padding |
| `base58` | Bitcoin alphabet |
| `be64(n)` | 64-bit unsigned big-endian |
| `len16(s)` | 16-bit unsigned big-endian length of `s` followed by `s` |
| `a ‖ b` | byte concatenation |

## 3. Layering

```
carriage (08)                envelope, X-SAGE-* headers
  message signatures (03)    RFC 9421 over the request and the response
    session records (05)     AEAD, sequence header, replay window
      handshake (04)         HPKE exporter and ephemeral agreement
        identity (06, 09, 10, 07)  naming, registry, resolution, agent card
          primitives (01, 02)      signatures, key encodings, canonical JSON
```

**OVERVIEW-02 (R-31, R-32).** This diagram is a conceptual dependency view, not a literal cyclic runtime stack. Identity permits signing; signed envelopes authenticate handshake participants; a successful handshake enables optional encrypted payloads. Execution authorisation is separate from transport authentication. Conformance requires all dependencies and version-matched tests; historical vectors cannot prove the new design.

## 4. Conformance levels

A conformance level names a set of requirements from `charter.md` §7. An
implementation states the level it claims and the specification version it
claims (§5).

| Level | Implements | Typical implementer |
|---|---|---|
| Verifier | Reads records and verifies messages and cards | a proxy or conformance checker |
| Peer | Verifier, and establishes sessions | an agent |
| Registrar | Verifier, and creates and maintains records | a registration tool |
| Reference | Every core level, and regenerates version-matched vectors | the reference cores |
| Execution Guard | Verifier and R-37..R-45; Peer when sessions are used | trusted Client/execution boundary |

## 5. Versioning and extension

**OVERVIEW-03 (R-34).** The target version is `0.10.0`, continuing earlier work
previously named `1.0.0-draft.1`. That historical label remains on its vectors.
This is a version-policy reset, not a claim of backwards compatibility.

A verifier MUST accept only an exact supported `0.x.y` version and MUST reject
missing/unknown versions without fallback. HTTP carries signed `X-SAGE-Version`;
chapter 08 envelopes and the execution profile carry their signed `version`.
All layers of one exchange MUST agree. A claimed supported version requires its
own implemented rules; merely changing a string is not conformance.

During 0.x, wire formats, rejection rules or labels may change with a MINOR
increment. PATCH changes clarify without changing accepted bytes or verdicts.
After a separately approved stable 1.0 release, breaking behaviour requires MAJOR;
optional compatible features use MINOR. Labels have independent domain-separation
versions; every changed label is recorded and implementations select by exact
protocol version, not by guessing from a suffix. Extensions follow chapter 11 and
cannot silently weaken existing checks. No follow-up release number is promised.

## 6. Normative status of this text

**OVERVIEW-04 (R-32, R-33).** This text and the explicitly normative integration profile are the specification. An ambiguity, a gap or a contradiction is a
defect in this text and is fixed here first, together with a planned test that pins the fix; implementation and version-matched vectors follow in the next phase. No implementation is normative.

Where this text cites a source file, the citation is informative: it records
where a rule came from, not what the rule is.

## 7. References

Normative:

| Reference | Title |
|---|---|
| RFC 2119, RFC 8174 | Key words for use in RFCs |
| RFC 5234 | Augmented BNF for syntax specifications |
| RFC 4648 | Base16, Base32 and Base64 data encodings |
| RFC 8032 | Edwards-curve digital signature algorithm |
| RFC 6979 | Deterministic usage of DSA and ECDSA |
| RFC 7748 | Elliptic curves for security (X25519) |
| RFC 7517, RFC 7518 | JSON Web Key, JSON Web Algorithms |
| RFC 8785 | JSON canonicalisation scheme |
| RFC 8439 | ChaCha20 and Poly1305 |
| RFC 9180 | Hybrid public key encryption |
| RFC 9421 | HTTP message signatures |
| RFC 9530 | Digest fields |
| RFC 8941 (as referenced by RFC 9421), RFC 9651 | Structured fields; see the applicability review for version differences |
| RFC 9457 | Problem details for HTTP APIs |
| W3C Decentralized Identifiers 1.0 | Identifier syntax, documents, resolution requirements |
| W3C Controlled Identifiers 1.0 | Verification methods, services, verification relationships |
| W3C DID Resolution | Resolution and dereferencing contract |
| CAIP-2 | Chain-agnostic chain identifiers |

Scope and process: [charter](../charter.md), [process](../PROCESS.md).
Reference applicability and errata are recorded in [standards review](../verification/standards.md). References inform the adopted rules; a future revision or reported erratum does not silently change this version.
