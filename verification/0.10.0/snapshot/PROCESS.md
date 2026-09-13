# Specification development process

## 1. Current delivery: 0.10.0

This updates the former `1.0.0-draft.N` work plan. The approved
[Seed](seeds/sage-spec-0.10.0.yaml) continues that work under **0.10.0**,
preserving existing chapters as the normative source. This is a documentation
design delivery, not a stable release, product implementation or security proof.
Historical vector versions are not relabelled. No tag, commit or publication is implied.

## 2. Stages and evidence gates

| Stage | Deliverables | Gate |
|---|---|---|
| Evidence and charter | Current X-bar document graph, AST graph, purpose/vision, trust boundary, R-1..R-45 | Provenance/exclusions, facts distinguished from interpretation, approved scope retained |
| Normative design (this delivery) | Updated 00..11, Agent/MCP profile, guide, traceability/inspector plan, repository roles/migration | Explicit encodings, rejection/recovery, all rule groups mapped to cases, no in-scope undecided verdict, review record |
| Implementation (follow-up) | Go/Rust libraries, SDKs, MCP, inspector, repository migration | Version-pinned builds, ownership contracts; old conformance not inherited |
| Verification (follow-up) | Independent positive/negative vectors, live cross-core exchange, host enforcement tests | Actual results with revisions, environments, case IDs and failure evidence |
| Security analysis (follow-up) | Formal models, adversarial review, measurements | Stated assumptions/properties, reproducible results and explicit limits |
| Stabilisation (future decision) | External review, candidate, errata process | Comments resolved, publication authorised, implementation/evidence gates satisfied |

No date/version is assigned to initial enrolment-compromise research. Design
completion, runtime conformance and security proof are different axes and the
[review](verification/review.md) reports them separately.

## 3. Source of truth and changes

**PROC-01 (R-32, R-33).** Normative text lives in `spec/`, the normative integration
profile in `profiles/`, and their scope in `charter.md`. Graphs record evidence;
they do not override rules. Code citations are informative. Ambiguities are fixed
in text, never decided by whatever the Go implementation happens to do.

Each normative rule group has a stable ID, requirements and inspector cases in
[traceability.json](verification/traceability.json). Each case defines input,
preconditions, expected acceptance/rejection or review outcome and evidence needed.
Statements inside a group inherit its mapping. Cases must cover distinct rejections
and transitions; a group label is not proof of executed coverage.

**PROC-02 (R-31..R-34).** Wire/behaviour changes record old/new rules, affected
implementations and planned tests. Old vectors remain historical. Follow-up creates
new version-pinned vectors instead of changing old version strings. Exact versions
are matched during 0.x; a minor change may be incompatible.

**PROC-03 (R-32, R-33).** Existing documents are updated in place; add documents only
for responsibilities not already owned. Current contradictions are removed or marked
historical. Source repositories and untracked user material remain untouched.

## 4. Document review

1. Assess each Seed outcome against content, not only file existence.
2. Map every requirement and normative group to planned cases, with no duplicate
   owner or contradictory transition.
3. Check graph IDs/endpoints, links, source snapshots and view scope.
4. Review wrong peers, replay, races, restart, revoked keys, malformed/large inputs,
   gate outages, direct bypass and check/use races as distinct cases.
5. Record unsupported profiles and excluded claims; do not hide an unfinished
   in-scope design behind an unspecified implementation choice.
6. Record document checks separately from unexecuted code, crypto and host tests.

Temporary artifact-inspection commands are not a delivered graph generator or
conformance implementation. No product test harness is built in this stage.

## 5. Inspector and maintenance

`sage-inspector` owns executable conformance checks; `sage-spec` owns their case
specification. A future run reports case ID, protocol version, implementation
revision, input fixture digest, expected/actual verdict and evidence. Unsupported,
missing and skipped cases are not passes. Wire checks cannot prove host isolation.

Amend a rule and its traceability together. Rebuild evidence when source snapshots
change. Follow the [migration plan](architecture/migration-plan.md) for later
repository separation; this process does not authorise immediate code migration.
