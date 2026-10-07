# Blockchain Registry connection preflight

The existing contract is not yet connected as an authoritative SAGE 0.10.0
Source. This review records the exact ABI and semantic mapping work needed
before configuring that connection; it does not select a chain deployment,
change the specification, upgrade a contract or certify a deployed address.

The [catalog](../verification/0.10.0/registry-contract-preflight/catalog.json)
pins sixteen committed files from four repositories:

| Repository | Reviewed revision | Responsibility |
| --- | --- | --- |
| `sage-contracts` | `d9f313b1057d299423d800c846751ed40282a116` | AgentCardRegistry/storage/hook, legacy interface, exported ABIs and export script |
| `sage` | `11b1cd91691de99fdbd734db78dc6755c187b2e9` | Current authoritative Source/Gate and named-key PoP contract |
| `sage-adk` | `fb98773df57b258c29ff9c355d062158bdf56c0e` | Exact-operation factory, instance measurement and final native binding |
| `sage-spec` | `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9` | Frozen Registry/DID rules, Agent/MCP profile and approved program sequence |

The [report](evidence/registry-contract-preflight.json) projects selected ABI
functions and preserves twelve manually reviewed source spans. Reading a Git
commit blob excludes dirty working-tree changes, so the separate ongoing spec
design branch is preserved. These are bounded source observations, not a
complete Solidity semantic, dependency or vulnerability audit. No compiler
or contract test program is invoked; ABI/compiler/deployed-code equivalence
remains unverified.

## Seven mapping obligations

| Area | Concrete current difference | Required connection work |
| --- | --- | --- |
| Exact ABI and record | `getAgent(bytes32)` in both exported ABIs has the same name/input types, but AgentCardRegistry returns `keyHashes` and twelve metadata members, while ISageRegistry returns `publicKey` and ten. Neither tuple directly exposes the closed normative record. | Select the exact deployment ABI and review its complete record/controller/key/service projection. A similarly named interface is insufficient. Wire and ABI field names need not be identical if their semantic mapping is established. |
| Named keys and retained state | AgentKey stores a numeric type, bytes, signature, verified flag and registration time; its record enumerates key hashes. Revocation removes the hash from that enumeration while retaining the key object. | Establish immutable names, role/algorithm mapping, proof signer identity and lifetime tombstones, including how retained historical keys are authoritatively enumerated. Do not infer an accepted key from a boolean. Optional expiry is not mandatory; its absence alone is not a violation. |
| Whole-record version | `agentNonce` changes on metadata, KEM and endpoint updates, but not every activation/deactivation/add/revoke mutation. Mutation calls do not take an expected previous record version. | Review atomic version increments and expected-version authorization for the complete record. Neither this nonce, timestamp nor block height is automatically the normative version. A reader alone cannot provide missing write-side semantics. |
| Terminal lifecycle | Initial inactivity and deactivation share the same `active` boolean. | Establish created/active/terminal deactivated state and authenticated transitions from reviewed authoritative evidence. Do not equate false with a specific lifecycle state. |
| Cryptographic proof | The reviewed Ed25519 branch checks only signature length. X25519 endorsement uses a separate wallet-domain challenge. | Validate the complete REG-04 named-key challenge and proof; bind KEM endorsement to the registered signing key and separate message-signing authority. `verified=true` does not establish this validation. |
| Claim and identity | Existing registration uses a keccak/ABI commitment and time windows; the DID hook checks a legacy prefix/length. REG-06 specifies domain-separated SHA-256/JCS claim bytes, block windows and canonical locator/agent identity. | Review read/write binding together. Preserve explicitly named legacy scope; do not silently downgrade the frozen profile or manufacture a conforming write mapping. |
| Actual providers | ADK Factory/Instance and core Source remain protected provider contracts. | Select actual loader/evaluator/tool/dependencies, key custody, finalized RPC observer and effect ownership. Hashes and fixture callbacks do not attest which code executes or which deployment state is authoritative. |

These differences block an *automatic assumption of compatibility*. They do
not mean every deployment must use identical ABI field names, nor do they
prove that no future reviewed resolver/contract binding can satisfy the profile.
Such a binding must establish all read and write semantics; custom projection
alone cannot repair lifecycle, authorization or claim-byte differences.

The exclusion for compromised initial creation/registration remains the later
1.1 design question. It does not turn a legacy flag into proof of key role,
current authority or safe later message/tool execution. This review does not
expand that previously agreed threat boundary.

## Reproduce without running inspected code

```sh
python3 -B scripts/test_registry_contract_preflight.py
python3 -B scripts/inspect_registry_contract_preflight.py \
  --contracts-root /path/to/sage-contracts \
  --spec-root /path/to/sage-spec \
  --go-root /path/to/sage \
  --adk-root /path/to/sage-adk \
  --check docs/evidence/registry-contract-preflight.json \
  --output /tmp/registry-contract-preflight.json
```

Query success means only that the reviewed committed sources, ABI projections
and saved report match. It is not connection authorization or a PASS for a
normative implementation case. Altered catalogs, missing commits/files,
symlink/nonregular Git entries, oversized blobs, hash/span drift, ambiguous
functions, malformed bounded ABI projections and saved report changes refuse
the query. A failed fresh query produces no report; callers must check status
and not reuse a stale output file. The Git object store and Inspector remain
trusted, and inspected working-tree content is neither used nor overwritten.

Units test ABI order/type preservation, tuple/scalar/array bounds, revision/hash
and catalog drift, report scope, ignored dirty worktree changes and safe CLI
refusal. The CLI also reproduces the actual four-repository committed review.
No inspected contract, loader, tool, RPC or attack-capable program executes.

## Next step in the existing order

Provide the selected network/chain ID, RPC trust/finality policy, Registry
address, deployed bytecode/upgrade identity and reviewed ABI/version. Also
identify the actual tool/loader/custody boundaries. Complete a reviewed binding
or explicitly record unsupported semantics; never synthesize `Validated`,
`Ready` or `Finalized` merely from a legacy response flag. Contract upgrades
remain in their approved later stage unless the user explicitly changes that
plan. Do not substitute the separate Web Registry for the blockchain boundary.

`binding_readiness` remains `REVIEW_REQUIRED`. Live chain, contract execution,
actual loaded-instance attestation, thirteen deployed host controls and
independent hop execution remain `NOT_RUN`; full conformance remains
`NOT_ESTABLISHED`. Historical evidence and the [remaining-work
register](remaining-work.md) keep their existing statuses and order.

The [subsequent mapping review](registry-mapping-review.md) classifies all
seven obligations into reader, writer and provider responsibilities, with
21 evidence requirements and six unbound record projections. It preserves
this preflight catalog/report unchanged and does not select a deployment or
establish a conforming connection.
