# Blockchain Registry read and write mapping review

The seven [preflight obligations](registry-contract-preflight.md) have now
been reviewed against the same four immutable repository revisions. This
completes a bounded **source mapping review**, not a deployment binding or
protocol conformance audit. A read-only conversion of the legacy contract
response does not establish compatibility with the frozen SAGE 0.10.0
Registry model.

## Outcome and required evidence

The [review ledger](../verification/0.10.0/registry-mapping-review/review.json)
contains all seven areas, six candidate public-record projections and **21
required evidence items**. The [reproducible report](evidence/registry-mapping-review.json)
classifies one area as reader mapping, five as requiring write semantics and
one as actual provider binding. These categories identify responsibility,
not completed fixes. Every evidence item remains `EVIDENCE_REQUIRED`; every
projection remains `NOT_BOUND`.

| Area | Classification | Evidence needed before a binding can be accepted |
| --- | --- | --- |
| Record and ABI | `READ_MAPPING_REQUIRED` | Exact deployment ABI/code identity; all six canonical fields; one consistent finalized read of metadata, keys and retained history. |
| Named key lifecycle | `WRITE_SEMANTICS_REQUIRED` | Immutable named/proven key history; active-only addition and lifetime limits; last usable signing-key revocation with atomic deactivation; distinct signing/KEM roles and deterministic named selection. |
| Whole-record version | `WRITE_SEMANTICS_REQUIRED` | Authenticated expected-version serialization; version one at creation and one increment for every successful mutation including grants; durable complete state/history and recovery. |
| Terminal state and operator authority | `WRITE_SEMANTICS_REQUIRED` | Authenticated lifecycle transitions with terminal deactivation; exact registry/DID/operator/operation scopes; atomic scope retirement and inspectable grant history. |
| Cryptographic proof | `WRITE_SEMANTICS_REQUIRED` | Complete self-named signing proof at write and read; signing-key endorsement of KEM with retained historical signer; real Ed25519 validation and explicit optional-algorithm support. |
| Claim and identity | `WRITE_SEMANTICS_REQUIRED` | Canonical chain/DID/controller binding; complete SHA-256/domain/JCS claim; controller-scoped block-window reveal and atomic consume/create followed by separate activation. |
| Actual providers | `PROVIDER_BINDING_REQUIRED` | Authoritative finalized Source and fresh observation; selected loaded tool/evaluator/dependencies and protected custody; pinned host with independent safe runtime observations and latency measurements. |

The detailed ledger keeps the three evidence requirements per area, reviewed
source line spans and their hashes. It also includes the normative Registry
sections for record, selection, lifecycle, proof, observation, eip155 and
operator transactions. This is not a Solidity parser proving semantics:
human conclusions are replayed only when the entire pinned sources and
ledger match. The additional anchors include the owner/operator modifier,
operator approval write, core Source contract and ADK Factory/Instance ports.

## What a reader can and cannot supply

The six public fields are candidates for a future complete reviewed binding:

| Normative field | Legacy candidate | Remaining semantic requirement |
| --- | --- | --- |
| `id` | `AgentMetadata.did` | Canonical DID belonging to the selected registry/agent. The bytes32 storage identifier is not this DID. |
| `controller` | `AgentMetadata.owner` | Exact lowercase chain-account principal, authenticated at the write boundary. |
| `keys` | `keyHashes` and `getKey` | Complete immutable named/proven history, including revoked entries. A raw hash cannot invent the historical signer URL; `kemPublicKey` is not a second authority store. |
| `services` | `endpoint` and `capabilities` | Reviewed bounded sorted name/type/HTTPS entries and complete atomic replacement. Neither arbitrary JSON nor one endpoint supplies this automatically; never fetch a URI to validate it. |
| `state` | `active` plus authoritative history | `false` alone cannot distinguish created from terminal deactivated. The actual write transition must enforce this distinction. |
| `version` | Complete authoritative mutation history | `agentNonce`, timestamps and block height are not the normative complete-record version. Expected previous version must also be enforced when writing. |

Algorithm enum values can be projected only through an explicit reviewed
mapping. Optional expiry need not exist; its absence is not a failure.
Keeping revoked key objects is useful, but complete authoritative enumeration,
immutable names and proofs remain required. Verifying a proof in the reader
is necessary and cannot certify that the registry validated a different
legacy proof on addition. A KEM endorsement does not demonstrate possession
of its private key or confer signing authority.

The expanded operator review matters independently of decoding. The pinned
`onlyAgentOwner` modifier accepts one blanket operator boolean, while the
spec defines a separate grant for each operation and authenticated durable
history. `activateAgent` checks existence, inactivity and elapsed delay but
not actor authority or terminal deactivation. Key/service writes do not
establish the required active-state and expected-version rules. These are
source observations, not executed exploit scenarios or claims about an
unspecified deployed address.

A local wrapper or resolver must not claim full write compatibility merely
because its own callers enforce extra checks: the binding must establish
which authority and direct mutation paths govern the record. This review
does not prove that a future complete reviewed contract/resolver binding is
impossible. It records why the present revision has no accepted binding.

## Reproduce the reviewed classification

Use the same pinned repositories declared by the original preflight catalog:

```sh
python3 -B scripts/test_registry_mapping_review.py \
  --contracts-root /path/to/sage-contracts --spec-root /path/to/sage-spec \
  --go-root /path/to/sage --adk-root /path/to/sage-adk
python3 -B scripts/inspect_registry_mapping_review.py \
  --contracts-root /path/to/sage-contracts --spec-root /path/to/sage-spec \
  --go-root /path/to/sage --adk-root /path/to/sage-adk \
  --check docs/evidence/registry-mapping-review.json \
  --output /tmp/registry-mapping-review.json
```

Nine scenario unit and safe CLI tests cover omitted areas/evidence/fields,
classification downgrades, fabricated field bindings, ledger/source/normative
changes, exact additional anchors and report scope. The actual CLI reads
committed blobs and reproduces the saved report; changing that report to
claim readiness or losing a repository refuses the query. No inspected code,
contract, loader/tool or RPC is invoked.

Exit zero means `SOURCE_REVIEW_COMPLETE` only. `binding_readiness` is
`UNRESOLVED`, `connection_authorization` is `NOT_GRANTED`, and
`read_only_projection_sufficient` is false. These are review-tool fields, not
wire protocol enums, a deployed conformance `FAIL` or an authorization API.
A failed fresh query writes no report; check its exit status and never reuse
an old output as a new successful observation. A saved JSON file is not a
signed attestation.

## Follow-up in the approved program order

Retain all seven obligations and their 21 evidence requirements when an
actual binding is proposed. Select the chain ID, trusted RPC/readiness and
finality policy, Registry address, deployed code/upgrade identity and exact
ABI/version, together with the tool/loader/evaluator/dependencies, custody
and independent effect observer. No deployment or provider was selected by
this source review. The existing thirteen deployed host controls and
independent hop execution remain `NOT_RUN`; full conformance remains
`NOT_ESTABLISHED`.

Do not amend the frozen specification to match the legacy contract or
substitute the separate Web Registry. Contract upgrades stay in the approved
later stage; the current review preserves those requirements for that work.
The excluded compromised initial creation/registration remains a later 1.1
design question, without excusing required later key/message/write checks.
Historical preflight, source inventory and runtime verdicts are preserved.
