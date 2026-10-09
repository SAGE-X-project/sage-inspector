# First-stage design and Inspector verdict

**Verdict: `TOOLING_READY` for the unreleased SAGE 0.10.0 design.** This is
the first stage of the [approved program sequence](https://github.com/SAGE-X-project/sage-spec/blob/85fee1830b2bc0d2420557df40796ae83073de12/architecture/program-sequence.md),
not an implementation, deployment, interoperability, or security conformance
verdict. The integrated INS-11 verdict remains `INCOMPLETE` and full
conformance remains `NOT_ESTABLISHED`.

The normative source is `sage-spec`
`85fee1830b2bc0d2420557df40796ae83073de12`, whose
[baseline record](https://github.com/SAGE-X-project/sage-spec/blob/85fee1830b2bc0d2420557df40796ae83073de12/verification/first-stage-baseline.json)
pins the unchanged normative bytes of source commit
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It records 45
requirements, 91 rule groups, 489 parents, 26 original mandatory children,
17 adopted Registry operator conditions, and 22 standards sources. The
separate `docs/design-and-integration-review` branch and its uncommitted
files were preserved. Its divergent contents had already received a
[disposition](https://github.com/SAGE-X-project/sage-spec/blob/85fee1830b2bc0d2420557df40796ae83073de12/verification/preserved-design-review.md);
the frozen normative chapters were not replaced by that older branch.

Inspector's [manifest](../verification/0.10.0/design-baseline/manifest.json),
[case contracts](../verification/0.10.0/design-baseline/contracts.json), and
[rule-line inventory](../verification/0.10.0/design-baseline/rule-clauses.json)
bind this exact revision. They include all 489 parents, the 26 original
children, all 17 operator conditions, and 13 Web Registry media conditions.
Each parent/child has a full-boundary contract as well as its prior bounded
fixture. In total there are 1,156 track-specific contracts: 562 retained
bounded fixtures, 32 newly required Registry tracks, and 562 full-boundary
tracks. Each contract names its rule, profile, subject owner, trusted
observer, exact input/expectation provenance, and required observation facts.
The source-line inventory pins every line in each rule span and the
otherwise-unowned Registry operator, non-HTTP MCP, compatibility, and
deployment clauses. Generation rejects an unowned capitalized normative
statement in the chapters, profiles, or charter.

The [evidence checker](../scripts/design_baseline_evidence.py) requires the
exact spec revision and selected profile, subject and runner revisions,
executable/adapter hashes, fixture and source hashes, an independent observer,
hashed evidence artifacts, actual outcomes and effect facts. It reports
`PASS`, `FAIL`, `PARTIAL`, `UNSUPPORTED`, and `NOT_RUN` separately. A bounded
fixture alone stays `PARTIAL`; a full case requires all source-line findings,
effect evidence, and a matching local fixture when that operation can be
tested locally. Unit simulations cannot yield full-case `PASS`. The catalog
CLI and evidence CLI self-tests exercise matching, mismatched, missing,
synthetic and old-revision evidence. A no-subject run reports **489/489
parents `NOT_RUN`** and **56/56 required subconditions unobserved**. This is
the truthful current implementation status, not a failure of catalog coverage.

The cross-repository check regenerates the catalog from the pinned spec and
compares it byte for byte. The spec's independent baseline check verifies all
source bytes, rule anchors, counts, and 22 standards-matrix rows. Inspector
checks that its Web media and operator suites have exactly the source bytes
adopted in the spec. The historical 481- and 489-case catalogs and their
revision-bound evidence remain untouched. New implementation observations
must be captured at the new revision; old PASSes do not transfer.

The [design-baseline runner](../scripts/run_design_baseline_cases.py) replays
the runtime fixture contracts whose input is a primitive operation through the
primitive bridge with the core adapter profile `primitive-foundation-010`.
That profile reaches 0.10.0 entry points only: strict canonical JSON
(`guard010`), the transcript-bound HPKE combiner and, when the adapter is built
with the `strictdid010` Go tag or Cargo feature, the strict 0.10.0 DID parser.
Operations whose only core implementation is a legacy API (legacy record
sessions, legacy sequence sessions, legacy key proof-of-possession and the
general X25519 primitive) report `UNSUPPORTED` instead of reaching it. The
default `primitive-foundation` profile keeps its historical behavior for older
evidence. Host-case and evidence-review fixtures stay `NOT_RUN` in this runner.

This closure permits the planned stage 2–3 library and Agent-client
integration analysis. The complete Go/Rust refactor, selected Agent-host and
Registry Source deployments, all case execution, public problem-type URIs,
independent consumers and organizationally independent external audit remain
in their later program stages. A future normative change reopens the baseline
and requires a new Inspector catalog before any implementation claim.
