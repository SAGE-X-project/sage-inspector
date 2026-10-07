# Sepolia Registry candidate code and source provenance

The unselected Sepolia candidate has a concrete published ABI and source
record. Its RPC-returned runtime bytes equal both runtime bytecode fields in
the Sourcify response, and the published ABI equals the pinned repository
ABI. **The published Registry source differs from the current pinned source.**
None of these comparisons selects a trusted Registry Source or establishes
SAGE 0.10.0 conformance.

The [observation record](evidence/registry-candidate-provenance.json) separates
RPC declarations, published verification claims and direct offline comparisons.
It supplements the [source mapping review](registry-mapping-review.md);
historical source reports, runtime verdicts and the approved work order remain
unchanged. This is a documentation update, with no new Inspector execution
path, connection adapter or protocol rule.

## Observed candidate

| Item | Observation |
| --- | --- |
| Network/address | Sepolia `11155111`, `0xc7ecf7ad6ee71cb0d94f0eb00f46f1ddf432a808` |
| Public RPC | `https://ethereum-sepolia-rpc.publicnode.com` |
| RPC observation | `2026-10-07T04:33:52.401633+00:00` |
| RPC-declared finalized block | Height `11860536`, hash `0x9c09dc2cbf37b2b0e199b14153969f75d0c1afdf1ae3fe863bec1fa6750bf8ee` |
| Returned runtime code | 20,762 bytes; SHA-256 `6781830872f71f12873c60b063f6507814a74932f99f3f6c5bf1a431af89edc5` |
| Published verification | Sourcify reports creation and runtime `exact_match`, verified at `2025-11-03T01:03:30Z` |
| Published compilation | `AgentCardRegistry`, solc `0.8.20+commit.a1b79de6`, optimizer enabled with 200 runs, Shanghai, `viaIR: false` |

Only `eth_chainId`, `eth_getBlockByNumber("finalized", false)` and
`eth_getCode` were queried. The code request used the returned block hash with
`requireCanonical: true`. The public RPC's chain/canonical/finalized declarations
were not independently checked against consensus or a selected trusted node.
No `eth_call`, signing, deployment, transaction submission or source verification
submission occurred. HTTPS certificate verification stayed enabled.

The lookup used the read-only [Sourcify v2 API](https://docs.sourcify.dev/docs/api/)
and its [candidate contract endpoint](https://sourcify.dev/server/v2/contract/11155111/0xC7eCF7Ad6ee71CB0d94f0eb00F46f1DDf432a808?fields=all).
The response's `runtimeBytecode.onchainBytecode` and
`runtimeBytecode.recompiledBytecode` each decode to exactly the RPC-returned
bytes. This is a direct byte comparison of retrieved records. Local independent
recompilation was not run. The service also reports `isProxy: false`; this
published claim is not an independently established upgrade or authority policy.

## Repository comparison

The contracts baseline remains
`d9f313b1057d299423d800c846751ed40282a116`. Git blobs were read at that
revision, independently of the working directory. Parsed JSON equality covers
all **64 ABI entries**, including their order, names, mutability and nested tuple
fields. The ABI match does not imply source equality or behavior compatibility.

Five published production files were compared byte for byte:

| File under `ethereum/contracts/` | Current pinned blob | Older blob at `4010cf41bb87f259b833e691b272cbaa4138d502` |
| --- | --- | --- |
| `AgentCardRegistry.sol` | Different | Equal |
| `AgentCardStorage.sol` | Equal | Equal |
| `AgentCardVerifyHook.sol` | Equal | Equal |
| `interfaces/ISageRegistry.sol` | Equal | Equal |
| `interfaces/IRegistryHook.sol` | Equal | Equal |

The only line difference in the compared Registry file is line 168. The
published source declares `bytes memory kemKey;`; the current source explicitly
initializes `bytes memory kemKey = new bytes(0);`, documenting the empty result
when no KEM key is supplied. This source observation does not substitute for a
runtime test of that path.

Published compilation paths refer to OpenZeppelin **5.4.0**, whereas the pinned
repository's `ethereum/package.json` declares `@openzeppelin/contracts` as
`^5.6.1`. A dependency range is not a complete build input. Neither the five-file
comparison nor the older matching files identifies a complete deployed Git
revision, dependency graph, build configuration or bytecode built from the
current baseline. No such equivalence is claimed.

The runtime trailer contains a 51-byte CBOR payload with solc release bytes for
`0.8.20` and the IPFS CID
`QmbHFCP1FHwz9AjfdEZ1WALJRhU4VLRUY6Z352qr4rDAJn`. These are metadata references.
The [Solidity metadata documentation](https://docs.soliditylang.org/en/latest/metadata.html)
explains the trailer and that source verification requires recompilation and
bytecode comparison. An IPFS CID is not the ordinary SHA-256 of the raw metadata
JSON. No CID content validation was performed here.

## Evidence and remaining boundary

The JSON record stores SHA-256 hashes of the raw RPC responses, raw Sourcify
response, both retrieved runtime bytecode values and compared Git/published
source bytes. Its ABI content hash uses UTF-8 JSON with sorted object keys and
compact separators, retaining array order. It also records the exact source
delta and the limited scope of each comparison.

The original bounded responses were retained in the investigation temporary
directory, not embedded in the repository. The compact JSON is an observation
record, not a self-contained replay fixture, signed attestation or automatic
conformance test. A future lookup must check its own response hash and time;
this dated observation is not a fresh Source snapshot. Downloaded contract
sources, Hardhat configuration and EVM bytecode were not executed.

The seven mapping areas and **21 evidence requirements** remain open. The
candidate still lacks an accepted 0.10.0 read/write binding, trusted finality
policy, complete record/key/proof observation and authenticated mutation
evidence. The six public-record projections remain `NOT_BOUND`. The thirteen
deployed host controls and independent hop execution remain `NOT_RUN`; full
conformance remains `NOT_ESTABLISHED`.

The next deployment decision remains selection of the chain/RPC/Registry
address and exact deployment version, together with the actual tool or MCP and
loader. Once those are selected, the approved mapping evidence must be supplied
before activating a Source or claiming compatibility. Required contract changes
stay in the previously approved later upgrade stage; the frozen specification
is not relaxed to fit this legacy deployment.
