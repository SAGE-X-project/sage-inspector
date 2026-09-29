# Charter

Status: **0.10.0 documentation design**, updated 2026-09-13 from the existing
charter. The [process](PROCESS.md) separates this delivery from implementation,
interoperability tests and security proofs. Rule groups have stable IDs and map
to the requirements below and the [inspector plan](verification/inspector-plan.md).

## 1. What is being standardised

SAGE specifies identity, authenticated message exchange and protected execution
integration for independently implemented software agents. It aims to reject
forgery, alteration and replay under explicitly stated trust assumptions, and
provide confidentiality for sessions. Registration supplies identity binding,
not general permission to execute an operation or proof of benign behaviour.

1. **Identity:** DID and Agent Card, registry model and profiles, registration,
   key possession/endorsement, resolution, rotation and revocation.
2. **Messaging:** request/response authentication, one-round-trip session
   establishment and directional record protection.
3. **Execution integration:** trusted original capture, authorisation of exact
   derived tool calls, component baseline verification and fail-closed dispatch.
   The [Agent/MCP profile](profiles/agent-mcp-security.md) is normative; concrete
   host hook APIs are implementation choices in the [guide](guides/integration.md).

### Out of scope for this delivery

Product implementation, actual repository splitting or code migration, new
graph-generator code, SDK/MCP/demo/service code, new executable test vectors,
inspector implementation, CI conformance execution and formal proofs are follow-up
work. Existing vectors remain historical evidence, not 0.10.0 conformance evidence.
Registry fees, addresses and administrative deployment choices belong to bindings;
payment, reputation and staking do not determine trust in this protocol.

## 2. Deployment models

| Model | Required interpretation |
|---|---|
| Agent to Agent | Both protected directions require registered active signing identities; Peer adds sessions |
| Agent to MCP server | Core verification may be one-way; Execution Guard requires an identified trusted executor and authenticated results |
| Gateway | A gateway holding a client's key is a trusted signing delegate inside its boundary; protection beyond that termination is not implied |

Each deployment MUST identify the conformance level and actual trusted termination
points. It MUST NOT advertise stronger guarantees merely because the transport
uses a SAGE message or a registered key.
In an A→B→C workflow, B's trusted Client is a new authorising boundary for a
B→C call. Authentication of A→B does not transfer the original user's authority
to B or C. The current version defines no transitive delegation credential.

## 3. Roles and trusted state

| Role | Responsibility |
|---|---|
| Agent | Sign, verify and optionally establish sessions using registered keys |
| Owner/controller and operator | Authorise lifecycle changes according to registry policy |
| Registry and resolver | Establish the authoritative identity/key state and observable revocation |
| Verifier | Reconstruct and verify messages, freshness, identity and required coverage |
| Trusted Client gate | Protect original requests, authorisation policy, keys and baseline hashes; authorise exact calls |
| Trusted execution gate | Pin verified inputs and executable components; mediate effects and durable call state |
| Untrusted component | Plugin, MCP tool, Skill or model-proposed content; cannot mint approval or disable verification |
| sage-inspector | Future conformance checker; this delivery defines its cases and evidence contract |

## 4. Assets and requested properties

| Asset | Property |
|---|---|
| DID/key binding | Authorised changes, coherent interpretation of the same authoritative registry state |
| Message | Authenticity, integrity, freshness and request/response binding |
| Session | Confidentiality, integrity, sequence/replay rules and a stated forward-secrecy goal |
| Registry state | Observable revocation with no added verifier grace; unavailable authoritative state fails closed |
| Trusted keys | Isolation from untrusted components and no transmission of private key material |
| User original and derived call | Immutable capture, explicit authorisation boundary, post-authorisation alteration rejection |
| Component baseline | Covered code/Skill/schema/config changes detected before the pinned instance executes |

## 5. Adversary and limitations

| ID | In-scope capability |
|---|---|
| A-1 | Read network bytes, headers and metadata |
| A-2 | Modify, drop, truncate, reorder or duplicate messages |
| A-3 | Replay to the same or another endpoint |
| A-4 | Use an attacker's own valid registered identity |
| A-5 | Race registration and substitute identifiers or keys |
| A-6 | Provide stale or selectively withheld registry observations |
| A-7 | Obtain a long-term private key after a completed session |
| A-8 | Modify Plugin/MCP/Skill code, dependencies, schema or configuration after clean enrolment |
| A-9 | Skip optional verification tools; use direct, nested, parallel, retry or restarted paths |
| A-10 | Substitute tool results, action, arguments or recipient while retaining identity |

| ID | Excluded claim |
|---|---|
| N-1 | Availability against volumetric denial of service; bounded work is required, universal availability is not promised |
| N-2 | Compromise of trusted capture, verifier, signing keys, policy/baselines or final execution gate; ordinary component compromise is covered by Execution Guard |
| N-3 | Universal detection of semantic prompt injection or proof that an LLM interpretation is correct |
| N-4 | Hiding traffic size, timing and endpoints |
| N-5 | Broken registry consensus or a stolen authorised registry controller account |
| N-6 | Agent creation, Card creation or registration already compromised, yielding an initially poisoned identity/baseline; follow-up investigation has no assigned release |
| N-7 | Proof that an upstream user's authority or intent is delegated across Agent hops solely by message signatures, parent IDs or DID registration |

A stored hash proves a comparison to an approved baseline, not remote runtime
attestation. A signature proves the signed bytes, not benign intent. An untrusted
component with unmanaged host privileges could act without messages: complete
mediation and isolation are prerequisites for the Execution Guard claim.

## 6. Requirements

The original R-1..R-36 identifiers are retained. Verification methods below are
obligations for follow-up evidence, not results already obtained. R-37..R-45 add
the approved execution integration scope.

### Identity, registration and management

| Id | Requirement | Tested by |
|---|---|---|
| R-1 | An agent is named by a `did:sage` identifier whose grammar is unambiguous and whose rejection rules are exhaustive | Vector, including rejected inputs |
| R-2 | An identifier names exactly one agent, everywhere. Two registries cannot issue the same identifier, and the identifier itself tells a verifier which registry to consult, so that an agent registered on one chain is never confused with an agent registered on another or with one registered outside any chain | Vector for the namespace component; review |
| R-3 | The specification defines a registry model that is not tied to one chain: the operations a registry must offer (create, read, update, revoke a key, deactivate, authorise an operator) and the properties a record must have. Each concrete registry is a profile of that model and declares its own identifier syntax, key types, signature algorithms and ownership proof, so that cryptographic differences between registries do not reach the other chapters. A registry that is not a blockchain is a profile like any other | Interoperability, one profile per core; review |
| R-4 | A record binds the identifier to its keys, its endpoint, its controller and an activation state. Every reader that sees the same registry state resolves the same binding | Vector for the record encoding; interoperability |
| R-5 | Registration is a claim that binds the identifier, the keys and the controller before it is visible, so that an observer of the claim cannot take the identifier or substitute its own keys. Where a registry cannot hide a claim, the profile states what it offers instead | Vector for the commitment derivation; model |
| R-6 | Each signing key in a record carries a proof that the registrant held the corresponding private key, bound to the identifier and to the key bytes | Vector, positive and tampered |
| R-7 | An agent becomes trustworthy only after activation, and a verifier must reject a message from a record that is not active | Vector for the state machine; interoperability |
| R-8 | A verifier must use only keys the registry marks as proven, must select among several keys by a rule stated in this text, and must reject a message whose key identifier does not name a key in the sender's record | Vector for the selection rule; interoperability |
| R-9 | A verifier rejects keys revoked or agents deactivated in the authoritative state observed under chapter 10. It adds no cache grace after observation; inability to establish acceptable authoritative state causes rejection. This is not instantaneous knowledge of unfinalised remote writes | Vector for the verdict after revocation; measurement of the delay between a revocation becoming observable and the first rejection |
| R-10 | Key rotation does not change the identifier, and a rotated-in key is usable only after its own proof is recorded | Vector |
| R-11 | Writes to a record are authorised to the controller or to a party the controller named; no one else can change a record | Interoperability; review of each profile |
| R-12 | A key-agreement key is published in the record, so that a session can be established with an agent that has never been contacted before | Vector; interoperability |
| R-13 | Registration, resolution and revocation have a stated cost/latency measurement plan; measured claims require published results in the follow-up verification phase | Measurement |
| R-14 | The identifier scheme is specified as a decentralised identifier method and produces a document that an independent DID consumer can parse using standard representations. Interoperability is an output-consumption goal to test; current authority and ownership still require the SAGE registry and resolution rules, not arbitrary third-party JWK members | Standard review; independent DID consumer and resolver tests |

### Message authentication

| Id | Requirement | Tested by |
|---|---|---|
| R-15 | Every protected message names the identifier of the party that signed it, and the signature covers that name | Vector |
| R-16 | A signature covers the request method, target, authority and, when a body exists, a digest of that body, so that A-2 cannot change what was asked without detection | Vector, including a tampered body |
| R-17 | A message carries a creation time and a unique value, and a verifier rejects one that is outside a stated window or that repeats a value it has already accepted for that key | Vector for the rejection; interoperability |
| R-18 | A response is bound to the request it answers, so a response cannot be moved to another request | Vector |
| R-19 | A verifier rejects a signature whose algorithm does not match the key type it resolved, and rejects encodings this text does not list | Vector, including rejected encodings |
| R-20 | Verification reconstructs the construction-defined signing bytes deterministically: HTTP digests use received content bytes and RFC 9421 bases; explicitly JCS-signed objects use the prescribed canonicalisation | Vector produced by an independent signer |

### Confidentiality and sessions

| Id | Requirement | Tested by |
|---|---|---|
| R-21 | A session is established in one round trip, authenticated to both identifiers, with no shared secret configured in advance | Vector; interoperability; model |
| R-22 | Session keys depend on a fresh ephemeral contribution from both sides, so that A-7 cannot decrypt a recorded session | Model; vector for the derivation |
| R-23 | Session keys are not derivable from the key-agreement material alone, nor from the ephemeral material alone | Model; vector |
| R-24 | Session records provide confidentiality and integrity, are ordered, and a receiver rejects a repeated or out-of-window record | Vector, including replayed and reordered records |
| R-25 | Keys are rotated within a session at a stated interval, and the rotation point is unambiguous to both sides | Vector at the rotation boundary |
| R-26 | A session is bound to the handshake that created it, so a record from one session is rejected by another | Vector; model |
| R-27 | The two directions of a session use different keys | Vector |

### Encoding

| Id | Requirement | Tested by |
|---|---|---|
| R-28 | Every signature construction has one unambiguous signing-byte procedure. JSON objects use JCS; HTTP signatures reconstruct RFC 9421 components from the received message. Parsers agree on duplicate and malformed-input rejection | Vector, including rejected documents |
| R-29 | Each key type has one wire encoding for public keys and one for signatures, stated with lengths | Vector |
| R-30 | Every field has a stated maximum size, and a receiver rejects anything larger before doing cryptographic work | Vector; measurement of the work done before rejection |

### Interoperability and process

| Id | Requirement | Tested by |
|---|---|---|
| R-31 | Independent Go and Rust implementations must pass version-matched vectors and a live exchange before interoperability is claimed; this delivery defines that plan rather than running it | Interoperability |
| R-32 | After the design stage closes, no implementation is normative: an ambiguity in this text is a defect in this text | Review |
| R-33 | Every normative rule group has a stable ID, requirement mapping and planned inspector input/expected-result or deployment review case. Pending evidence is explicit; unimplemented design rules remain normative | Generated coverage matrix |
| R-34 | An implementation can state the version it conforms to, and a verifier can refuse a version it does not implement | Vector for the version field |

### Operational

| Id | Requirement | Tested by |
|---|---|---|
| R-35 | An authentication failure returned to a sender does not reveal which check failed | Review; conformance checker |
| R-36 | A responder does public-key or registry work only after the cheap checks it can make first | Measurement; conformance checker |

### Agent and MCP execution protection

| ID | Requirement | Planned verification |
|---|---|---|
| R-37 | Trusted capture and linkage to each exact authorised derived call at every Client hop; an upstream signed message alone never grants downstream execution authority | IG-01 |
| R-38 | Altered recipient, tool, arguments, policy or original commitment is rejected before effects | IG-02 |
| R-39 | Prompts, approval bypass, direct calls, missing verdict, timeout and disconnect cannot bypass verification | IG-03 |
| R-40 | Protected baseline hashes are checked before loading and bound to the executable instance | IG-04 |
| R-41 | Concurrent calls and restart preserve replay control; unknown outcomes do not auto-execute again | IG-05 |
| R-42 | Results bind to exact calls and are verified before consumption | IG-06 |
| R-43 | Signing and enforcement are isolated from untrusted components; no unrestricted signing oracle | IG-07 |
| R-44 | Required integration points are host-independent; unsupported hosts cannot claim Execution Guard | IG-08 |
| R-45 | Claims distinguish integrity from semantic safety, remote attestation and whole-host compromise resistance | IG-09 |

## 7. Conformance levels

| Level | Requirements | Typical implementer |
|---|---|---|
| Verifier | R-1, R-2, R-4, R-7..R-9, R-15..R-20, R-28..R-30, R-34..R-36 | message/card verifier |
| Peer | Verifier plus R-12, R-21..R-27 | session peer |
| Registrar | Verifier plus R-3, R-5, R-6, R-10, R-11, R-14 | registration service |
| Reference | all core levels plus reproducible version-matched vectors | Go and Rust core implementations |
| Execution Guard | Verifier plus R-37..R-45; Peer if sessions are used | integrated Client and trusted executor |

R-13, R-31..R-33 govern evidence and specification development across levels.
Code compliance, deployment-boundary compliance and security proof status are
reported separately; none is inferred from file existence or a version string.

## 8. Design deliverables

Update existing chapters 00..11 rather than create a competing specification.
Maintain the [evidence graph](analysis/graphs.md), [purpose and vision](analysis/purpose-and-vision.md),
[integration profile](profiles/agent-mcp-security.md), [guide](guides/integration.md),
[inspector plan](verification/inspector-plan.md), [traceability matrix](verification/traceability.json),
and [repository boundaries](architecture/repository-roles.md). Concrete source
citations are informative. No implementation fills an ambiguity in normative text.

## 9. Decisions for 0.10.0

| Decision | Disposition |
|---|---|
| Prior registration | Required identity trust path; it does not authorise every registered peer |
| Revocation | No positive-cache grace after authoritative observation; finality/observation latency is explicit |
| Registry independence | Shared model with explicitly supported profiles and binding prerequisites; unknown or incomplete profiles fail closed |
| DID interoperability | Canonical method syntax and document projection; external interoperability remains unverified |
| Version | Continue existing work as 0.10.0, superseding the draft naming without erasing history |
| Compatibility | Security corrections may break existing implementations; implementations follow the new text |
| Execution | No mandatory user prompt; mandatory code-level verification and no silent downgrade |
| Hooks | Mechanism is optional; interception and fail-closed outcomes are mandatory for profile conformance |
| Evidence | Documentation completeness is not runtime conformance or proof of security |
| Initial compromise | N-6 deferred without promising 0.11 or 1.1 |
| Multihop authority | Each trusted Client independently captures and authorises its outgoing call; parent IDs are causal only, and no transitive delegation is defined |

## Evidence reporting — EVIDENCE-01 (R-13, R-31, R-33)

Measured costs, interoperability and rule coverage MUST identify their executed
inputs and implementation revisions. A planned case, document check or successful
source comparison MUST NOT be presented as protocol execution or security proof.
This explicit group label preserves the existing EVIDENCE-01 traceability ownership.
