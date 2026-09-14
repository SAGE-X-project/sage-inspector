# Integrated evidence and coverage — 0.10.0

The integration joins 45 requirements, 77 rules and 386 planned cases to selected
raw observations. Run from the Inspector repository:

```sh
python3 scripts/integrate_evidence.py --output /tmp/sage-evidence.json
python3 scripts/integrate_evidence.py --check --output docs/evidence/integrated.json
python3 scripts/test_evidence_integration.py
```

Exit 0 means that the evidence inventory and report are consistent. It is not a
core conformance result. Invalid, missing or changed evidence returns 2.
`--require-conformance` returns 3 after valid evidence generation/checking because
complete protocol conformance is not established. Existing output files are never
overwritten; use a fresh path or `--check`.

## Archived observations

| Core | PASS | FAIL | UNSUPPORTED | Stateful scenarios NOT_RUN |
|---|---:|---:|---:|---:|
| Go `c7709b7486e0da94336edc0931fddd87f6a45343` | 145 | 69 | 311 | 97 |
| Rust `206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2` | 159 | 63 | 303 | 97 |

Each core has 525 primitive cases in ten suites and 97 prepared scenarios with
648 steps. All 386 planned cases remain NOT_RUN as complete normative scenarios.
These units must not be subtracted or used as a protocol pass percentage.
Session rejection observations do not establish isolated defenses when positive
controls fail. The Guard primitive passes cover JCS/signature projections only.
Six HTTP size cases remain conditional pending normative byte-count clarification.

`verification/0.10.0/evidence-catalog.json` explicitly selects reports; old duplicate
HTTP reports and reference-adapter reports are excluded. Every input is pinned by
SHA-256, including the exact dirty specification snapshot, vectors, case map,
core source lock and historical provenance attachments. Hashes detect drift from
this reviewed inventory; they do not authenticate an attacker-replaced inventory.
Historical adapter source hashes describe the corresponding run and are not
assertions about the current adapter source tree.

The deterministic `docs/evidence/integrated.json` includes:

- Requirement → rule → planned case links, and rule → primitive/scenario links.
- Partial foundation-to-case links already reviewed in the baseline. Shared rule
  IDs alone never become exact case coverage or a rule/requirement PASS.
- Per-run subject name, core revision, executable hash, environment and time.
  Different historical adapter builds remain separate even at the same core revision.
- Raw report paths and result indices for exact inputs, expectations and observations;
  pinned fixtures hold scenario inputs and expected effects. Missing actual effects
  are null, never zero.
- Separate observation results, partial/conditional/prepared/unmapped coverage and
  NOT_ESTABLISHED conformance. No aggregate whole-protocol PASS is emitted.

## CI and reproduction

The `Evidence integrity` job checks the frozen baseline, mutation tests and the
committed aggregate, then reruns the reference foundation against its frozen suite.
The reference execution is a fresh Inspector self-check, not a core run. Independent
Node fixture audits and Go race/vet/build checks remain in the Test job. The legacy
spec-vector job is explicitly named and pinned independently of the revised profile.

The CI artifact contains the integrated report, raw evidence, specification archive,
fixtures, catalog, audit scripts and fresh reference report, plus CI revision and
runtime metadata. It preserves the bytes needed to trace each result without sibling
repositories. CI success verifies Inspector tooling and evidence integrity; expected
archived core failures remain visible and do not make that CI check fail.

For a new core run, build the existing real adapter against its recorded source
revision and run the suite/bundle commands in the linked inspection documents.
Use a new output directory. Review the raw reports, update the catalog's explicit
report paths, revision/source lock and SHA-256 entries, then generate a new aggregate.
Do not hand-edit the aggregate. Merely adding a file under `docs/evidence` does not
select it. A missing primitive report is an inventory error, not a zero-count run.

When a real schema2 binding exists, `cores[].scenario_reports` maps a prepared
scenario ID to a pinned raw report path. The integration validates every step,
observed result/effect and stop progression and preserves per-step effects. Omitted
bindings remain NOT_RUN. Test-generated reports only exercise this ingestion path;
they are never included in core evidence. Actual host bypass, chain deployment and
Go↔Rust interoperability evidence remain separate follow-up work.
