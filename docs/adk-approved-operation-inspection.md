# ADK approved operation source inspection

This adds an explicitly selected Inspector query for `sage-adk`
`fb98773df57b258c29ff9c355d062158bdf56c0e`, which introduced
`core/guardbinding`. It keeps the existing normative SAGE 0.10.0 pin
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9` and the same thirteen deployed
host-port controls. It changes no protocol or wire requirement.

The [reviewed catalog](../verification/0.10.0/adk-approved-operation/catalog.json)
hashes all 169 tracked non-test Go files and both module files. The
[saved source query](evidence/adk-approved-operation.json) contains 49 reviewed
declaration/call anchors: the preceding 29 route classifications plus 20
`APPROVED_OPERATION_OPT_IN` boundaries. Hashing the entire production source
set does not classify every declaration or establish a complete effect graph.

The earlier [route report](adk-source-inventory.md), catalog and evidence stay
at `afa469cdd8539992185235008ac1591c74012f7f`. That snapshot remains the CLI
default. Neither report is promoted from source evidence to deployment evidence.

## Reviewed boundaries

| Boundary | Source review | Obligation still outside this query |
| --- | --- | --- |
| `Open` and `parseRules` | Exact policy/component commitments, owned artifact bytes and fixed local recipient/key/tool/arguments/lifetime precede publishing an Operation. | Trusted administration selects the policy independently of model proposals and maps it to the original request. Digests do not prove natural-language equivalence. |
| `Operation.read`, `readFile`, platform file opens | Confined bounded regular-file reads and exact hash checks; Linux/macOS no-follow/nonblocking final opens; unsupported platforms refuse. | Protect and serialize intermediate filesystem mutation. Parsing both build-tag variants is not observation of platform selection or OS isolation. |
| `Snapshot` accessors and `Factory.Load` call | The factory receives defensive artifact/descriptor copies and supplies one fixed instance. | The provider must load only those approved evaluator/tool/dependency bytes and retain resource ownership. No concrete universal loader is supplied. |
| `Bindings`, `Authorize`, `ApproveIntent`, `Check` | Fixed request/issuer/tool/arguments and closed root intent fields are checked with fresh capture, files and mandatory instance measurement. Capture/files are checked again after the external measurement callback. | `Instance.Check` must establish actual loaded-code identity; echoing digests is insufficient. Core owns current authority/time, one-use approval and durable fencing. Parent-hop policy needs a separate binding. |
| Private `loaded.Execute` and `Operation.Binding` | The same instance receives copied exact arguments after current checks under the shared execution gate. | Keep Binding.Tool, Factory and Instance with protected host configuration. Ordinary Tool Registry, Agent, A2A and gRPC effects remain separate routes. |
| `Operation.enter` and `Close` | Retirement refuses new callbacks and waits for an accepted bounded effect/cleanup before closing artifact custody. | Providers must honor cancellation/bounds. Administration still owns factory lifetime, durable policy epochs, distributed retirement and uncertain-completion reconciliation. |

These are manual classifications tied to exact hashed source. AST matching only
confirms named declarations and syntactic calls at reviewed lines. It does not
prove call ordering, data flow, type identity, condition enforcement, runtime
reachability, absence of other effects or trusted provider behavior. Whole-source
hashes refuse changes to expressions/constants even when anchor names survive;
changed revisions require deliberate new review rather than automatic repinning.

## Reproduction and refusal tests

Build the trusted parser from Inspector, then use a clean, quiescent ADK checkout
at the exact new revision:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot approved-operation \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-approved-operation.json \
  --output /tmp/adk-approved-operation.json
```

The snapshot selector accepts only reviewed names. A mismatched revision,
catalog/hash change, dirty source, ignored untracked Go source, changed source
set, missing/duplicate anchor, symlink, oversized source or parse failure refuses
the query. Catalogs from different revisions cannot be substituted. The report
is assembled only after source checks before and after parsing; a failed fresh
query creates no report. These checks assume trusted quiescent storage, not a
concurrently hostile filesystem. Callers must check process status and must not
reuse an older output file as evidence of a failed new invocation.

Units cover snapshot separation, reviewed catalog and provenance refusal,
scope preservation and integrity of the execution/measurement/retirement anchors.
Safe parser-CLI runtime tests parse inert source containing an unexecuted panic
and an absent dependency; source code is never imported, built or run. Both actual
ADK snapshots are parsed and compared with their saved reports. CI pins separate
public checkouts and reproduces both reports with the same Inspector-built parser.
No attack-capable vulnerability or host-bypass program is introduced.

## Remaining work in the approved sequence

The source query result is `AST_QUERY_EXECUTED`; ADK runtime is `NOT_RUN`,
effect observations are absent, host selection is `SELECTION_PENDING`, all
thirteen deployed host-port controls and independent hop execution are `NOT_RUN`,
and full conformance is `NOT_ESTABLISHED`. ADK's own local arithmetic/runtime
tests remain separate integration evidence with fixture Registry and loader
providers; they are not copied into this source verdict.

The exact-operation helper now supplies concrete local policy/snapshot and
same-instance native binding code. Actual protected loader attestation and final
effect inventory remain host responsibilities. Identify the authoritative
blockchain Source's chain ID, RPC, Registry address, ABI/bytecode version and
finality policy before observing it. Then select and pin the host executable,
configuration, provider ownership, supported effects and independent observer,
and run the existing Inspector host controls. Complete independent parent-hop
binding separately. The [remaining-work register](remaining-work.md) and approved
program order remain unchanged; this does not start demo work or later normative
A2A/DID upgrades.

The subsequent [blockchain connection preflight](registry-contract-preflight.md)
records exact ABI/record/proof/lifecycle mapping differences in the existing
contract candidate and the actual loader/provider decisions needed for assembly.
It preserves these source-query limitations and all deployment verdicts.
