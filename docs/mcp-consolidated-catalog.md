# Consolidated MCP proposal catalog

Inspector pins the integrated proposal at sage-spec
`70abcda876879697cae91f1182ce5c9148211e8d`, independently of the earlier 40-case
setup model. The [snapshot manifest](../verification/0.10.0/mcp-consolidated-proposal/manifest.json)
identifies five exact source files. This is a focused snapshot: links within the copied
proposal refer to ancillary documents in the source repository at that revision.

The checker validates the pinned manifest itself, source hashes, distinct case IDs,
case grouping and nonpromotion. It reports original 40, addendum 18 and resolution 13
cases as 71 NOT_RUN, with their originating rule/obligation/finding. It does not adopt
normative rules, prove scenario semantics or run the protocol. Historical lifecycle
37 NOT_RUN and conformance NOT_ESTABLISHED remain unchanged. The earlier 812-state
model and its report remain frozen and do not cover the new admission/deadline rules.

Run from the Inspector repository:

```sh
python3 -B scripts/test_mcp_catalog.py
python3 -B scripts/check_mcp_catalog.py --output /tmp/new-mcp-catalog-report
```

The output directory must be new and outside the repository. Existing output and
historical evidence cannot be overwritten. CI retains the catalog as a separate
`mcp-proposal-catalog-<revision>` artifact with the source manifest, Inspector revision,
checker hash and per-case status. CATALOG_CHECKED is not protocol PASS.

The tests include negative unit controls and real bounded CLI processes. They verify
catalog integrity and report preservation, not cryptographic exchanges. Actual core
bindings and protocol execution remain NOT_RUN. Next: review/adopt the consolidated
normative contract before implementing the corresponding owner API and safe runtime
interoperability. Missing independent external review is not satisfied by this checker.

The separate [runtime evidence overlay](mcp-case-evidence.md) now derives current
results without modifying this snapshot. It records one close/admission resolution
case as `PASS`, one as `PARTIAL`, and leaves 69 current cases `NOT_RUN`. This catalog
report itself remains 71 `NOT_RUN` by design.
