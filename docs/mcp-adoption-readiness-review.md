# MCP proposal adoption-readiness review

This review examines the frozen consolidated non-HTTP MCP proposal after completion
of the 71-case Inspector evidence overlay. It is an internal bounded rereview that
examines the frozen text separately from runtime evidence. It is not an external
independent security review.

The review pins the proposal manifest and text, the complete tool descriptor, and the
MSET and aggregate evidence contracts. It found six adoption prerequisites:

| Finding | Severity | Status | Required decision |
|---|---|---|---|
| `ADOPT-01` | HIGH | OPEN | Resolve the conflict between the general callback prohibition during `OUTPUT_PENDING` and the active send-completion callback that must publish through the owner. |
| `ADOPT-02` | HIGH | OPEN | Choose and specify the READY-state protected-call concurrency limit, response ordering, backpressure, deadline and close behavior. |
| `ADOPT-03` | HIGH | OPEN | Assign a stable local binding identifier and pin the complete descriptor digest so preconfigured peers cannot select different revisions. |
| `ADOPT-04` | HIGH | OPEN | Reconcile the accepted rules into one normative profile, traceability map, compatibility record and changelog revision. |
| `ADOPT-05` | MEDIUM | OPEN | Link the current Inspector execution evidence from the adoption record while preserving the historical `NOT_RUN` plans. |
| `ADOPT-06` | MEDIUM | PENDING_EXTERNAL | Obtain review by an independent external reviewer after the other findings are resolved in one candidate revision. |

`ADOPT-01` is a textual state-machine conflict rather than a demonstrated runtime
failure. Existing synchronous-completion tests show one implementation choice, but
the normative text must say that the active output completion is the controlled
exception and that unrelated callbacks retain no authority.

`ADOPT-02` does not assume that concurrency is required. A single-flight profile is
acceptable if stated explicitly and if an additional protected attempt has a defined
fail-closed outcome. If concurrency is allowed, correlation and publication ordering
must be specified without weakening the one-output barrier.

`ADOPT-03` does not require a new wire field. The proposal deliberately rejects
in-band negotiation, so a versioned identifier and descriptor digest can be trusted
deployment configuration. Construction must fail before setup when the configured
baseline differs.

The historical 40 original, 18 addendum and 13 resolution plans remain 71 `NOT_RUN`
records. Inspector's separate runtime overlay currently derives 71 PASS observations.
`ADOPT-05` requires an adoption record that points to those contracts and CI artifacts
without rewriting the historical planning status.

Run the bounded document control and CLI report with:

```sh
python3 -B scripts/test_mcp_adoption_review.py
python3 -B scripts/check_mcp_adoption_review.py \
  --output /tmp/new-mcp-adoption-review
```

A successful checker result means the review source and open findings are intact. It
does not mean the findings are resolved. Adoption readiness remains `BLOCKED`, the
proposal remains `PROPOSAL_NOT_ADOPTED`, external review remains `NOT_PERFORMED`, and
conformance remains `NOT_ESTABLISHED`.
