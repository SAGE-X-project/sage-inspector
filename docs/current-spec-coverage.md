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

The gap report distinguishes the 386 baseline cases, 71 earlier MCP cases,
eight Registry clarification cases, and 16 later correction cases. Only eight
baseline cases have related primitive prerequisites; these do not establish
complete case coverage. Generate it with:

```sh
python3 -B scripts/current_spec_gap.py --output /tmp/current-spec-gap.json
```

`scripts/current_spec_evidence.py` is the case-level evidence admission and
status engine. Its first twenty bindings are partial JCS parser, integer,
canonical-byte, and proof-exclusion fixtures;
the remaining cases still need bindings. A binding must name a current
case or mandatory child, one required verification track, a repository-owned
fixture hash, and whether that fixture covers the complete case or only part
of it. An external observation must pin the spec revision, exact fixture and
input hashes, subject repository/revision/executable hash, runner revision,
environment, and typed verdict/output/effect counters. The engine compares
the independently stored expectation with the observation; it does not accept
a self-reported `PASS`. Missing bindings and observations remain `NOT_RUN`,
reported lack of subject support is `UNSUPPORTED`, an observed mismatch is
`FAIL`, and a matched partial fixture is `PARTIAL`. Every required track and
mandatory child must pass before a parent case can pass. Even then overall
conformance remains `NOT_ESTABLISHED` until the separate integration gates
are satisfied.

```sh
python3 -B scripts/test_current_spec_evidence.py
python3 -B scripts/current_spec_evidence.py \
  --evidence /path/to/revision-bound-observations \
  --output /tmp/current-spec-evidence.json
```

The unit tests use synthetic, inert observations to check status derivation.
They are not evidence that a SAGE implementation passed a normative case.
`scripts/run_current_spec_cases.py` can execute bound runtime fixtures against
one explicit local adapter. It sends the case input but never the expected
answer, bounds the process, and writes hashed observations for the evidence
engine. Document and deployment reviews use their own observation capture;
they cannot be replaced by a primitive adapter. An attempt to run a case
without a reviewed runtime fixture fails explicitly. The primitive bridge
translates the seven JCS parser cases to the existing Go/Rust core adapter request,
preserving raw JSON bytes and returning only the core verdict. Its
empty effect map means effects were not observed; this is partial case evidence.
For JCS-02, the bridge submits both signed Guard intents and records the
control and candidate verdicts from the receiving schema path.
The first [Go/Rust JCS observation](current-spec-jcs-evidence.md) records one
Go mismatch and one Rust partial match. The expanded
[JCS parser observations](current-spec-jcs-parser-evidence.md) record all six
parser scenarios. The [signed integer observations](current-spec-jcs-integer-evidence.md)
record five JCS-02 scenarios using valid signed controls without promoting
overall conformance.
The [canonical-byte observations](current-spec-jcs-canonical-evidence.md)
record four JCS-03 byte relations against both cores, also as partial cases.
The [proof-exclusion observations](current-spec-jcs-exclusion-evidence.md)
record four JCS-04 Agent Card cases as `UNSUPPORTED` because neither current
core adapter exposes the 0.10.0 card verifier.

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
