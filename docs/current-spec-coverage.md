# Current 0.10.0 specification coverage

The current inventory is pinned to `sage-spec` revision
`5bcf511e604579afa63f434013447f44b6858828`. It contains 45 requirements,
91 rule groups, 481 parent cases and 26 mandatory subscenarios. The previous
386-case INS-01 snapshot and its evidence remain historical. They are not
rewritten or counted as observations of this revision.

`scripts/current_spec_catalog.py` verifies the current traceability snapshot,
every requirement-to-rule and rule-to-case relationship, the 386 historical
case classifications, 95 additional case classifications, all mandatory
subscenario parents, and hashes of every normative source file cited by the
rules, the MCP tool descriptor, and the standards-clause audit. `MOWN-06` is
a cross-case mandatory-child mapping rather than a rule
with its own parent cases. CI checks these identities against the pinned
`sage-spec` checkout. New or removed cases, changed source files, and
reclassified historical cases require an explicit catalog update.

Run the inventory locally with:

```sh
python3 -B scripts/test_current_spec_catalog.py
python3 -B scripts/current_spec_catalog.py \
  --spec-root /path/to/sage-spec \
  --report /tmp/current-spec-inventory.json
```

The report enumerates all 481 cases and their applicable verification tracks.
Its statuses are `NOT_RUN` and its conformance verdict is `NOT_ESTABLISHED`.
The inventory answers whether Inspector knows every normative case. It does
not answer whether a Go or Rust core, MCP host, Registry Source, or deployed
system passed that case. In particular, related primitive vectors and rule
IDs are not complete parent-case evidence.

The 95 cases added after the historical snapshot comprise 71 MCP cases and
24 later corrections. The older 71-case MCP runtime overlay is useful bounded
evidence, but it was captured against an earlier spec revision; this inventory
does not automatically promote it. The eight later Registry cases have only
one partial exact-byte PoP observation and seven unrun cases. The remaining
16 later cases do not yet have case-specific Inspector execution evidence.

Complete support requires a version-matched evidence binding and an
independent verdict for every case and mandatory subscenario, including
document and deployment review where the case demands it. Each bound result
must retain the spec revision, implementation revision, exact fixture and
observation, and applicable effects. Any absent binding remains `NOT_RUN` or
`UNSUPPORTED`; an observed mismatch is `FAIL`. Implementation-specific tests
may be added separately but cannot substitute for missing normative cases.
The current `sage-spec` standards-clause audit also records an unresolved
HTTP algorithm conflict; Inspector cannot assign a conforming expected
verdict for that boundary before the normative decision is made.
