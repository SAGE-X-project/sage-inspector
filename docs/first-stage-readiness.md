# First-stage specification and Inspector readiness

The [SAGE program sequence](https://github.com/SAGE-X-project/sage-spec/blob/1820ab5eafb843e1c13f4c46c34aeeb28d934ac9/architecture/program-sequence.md)
places `sage-spec` and `sage-inspector` before core refactoring. This stage
completes the protocol design and its independent inspection capability.
It does **not** require current Go/Rust cores or an Agent host to pass all
implementation cases. Missing subjects remain `NOT_RUN` or `UNSUPPORTED`.

## Exit criteria

1. `sage-spec` publishes one reviewed 0.10.0 normative revision. Chapters,
   both MCP profiles, rule IDs, standards decisions, rejection semantics,
   compatibility, vectors, traceability and change history agree. Preserve
   historical revisions and the separate design branch.
2. Inspector regenerates a complete case catalog from that exact revision.
   Every normative obligation has a stable case or required child assertion,
   an independent expected outcome, evidence type, and owner. The current
   [489-parent/26-child inventory](latest-spec-inventory.md) is an input, not
   an immutable count if the final specification changes.
3. Each case has a usable inspection contract: fixture and independent
   checker where a local byte/verdict test is possible, or a typed host or
   deployment observation contract where external authority is essential.
   The latter must identify the required subject, trusted observer and facts
   needed for a verdict. A placeholder or a source citation alone is not
   executable coverage.
4. Inspector reports exact protocol/profile and subject revisions, fixture
   and runner hashes, expected and actual outcomes, and separate `PASS`,
   `FAIL`, `PARTIAL`, `UNSUPPORTED` and `NOT_RUN` states. Unit checks and safe
   bounded runtime checks verify the Inspector's own parsing, independent
   expectations and evidence rules. Implementation-dependent cases do not
   become `PASS` from these self-checks.
5. A cross-repository review confirms that the frozen rules and Inspector
   contracts agree on accept/reject bytes and boundaries. Any contradiction
   returns to `sage-spec` first, then receives a versioned Inspector update.

The [first-stage completion record](first-stage-completion.md) now closes
these design and Inspector-tooling criteria at the byte-pinned 0.10.0 source
revision. All 489 complete implementation cases remain `NOT_RUN` against
that revision until actual subjects and independent observations are bound.
The [INS-11 integrated verdict](ins11-integrated-verdict.md) remains
`INCOMPLETE` and conformance `NOT_ESTABLISHED`.

## Work order inside this stage

1. Review and freeze the normative source without overwriting the preserved
   `sage-spec` design branch or historical evidence.
2. Rebuild the requirement/rule/case inventory and identify missing or
   ambiguous case expectations.
3. Complete independent fixtures and typed inspection contracts, especially
   for the latest eight `msca-*` cases and host-dependent obligations.
4. Run Inspector self-tests and available safe local bindings; retain exact
   `NOT_RUN`/`UNSUPPORTED` results where a core or deployment is absent.
5. Review the source-to-Inspector map and record a first-stage readiness
   verdict. Only then begin the importable-core and Agent-client integration
   analysis in program stages 2–3.

Full Go/Rust conformance, the Registry Source and Agent-host deployment runs,
external organizational audit, SDKs, facilitator, discovery and chain work
are later stages. Future integration analysis can reveal a necessary spec
change; program stage 4 requires that change to be reviewed and reflected in
Inspector before the cores implement it.
