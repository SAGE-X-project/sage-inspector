# Counterexample review of authenticated MCP setup

Reviewed revision: `48858011b75f69c72f03c0fde1c17a1edc538815` (first proposal).
Method: a separate counterexample-oriented pass by the **same authoring agent**.
This is not an independent external review, formal verification or a deployed
vulnerability finding. The conclusions below are design inferences from the text.
The [machine-readable record](review.json) pins the original input and corrected
artifacts; the [case plan](cases.json) preserves all execution statuses as NOT_RUN.

## Findings and revisions

| Finding | Original gap and counterexample | Revision | Design severity |
|---|---|---|---|
| output-publication | State advanced when bytes were prepared, before I/O. A concurrent protected input could observe READY while the listing send was still pending and subsequently failed. | OUTPUT_PENDING blocks state publication and dispatch. One bounded deferred frame may be processed only after local send success and final owner/deadline/session checks. Uncertain completion closes. | High |
| request-id-history | Fresh setup IDs were required but lifetime uniqueness across setup and a newly created protected endpoint was not explicit. An old initialize ID could be reused after setup history was discarded. | One bounded connection-owned history includes setup and protected request IDs; endpoint construction cannot reset it. Reuse/exhaustion closes before effects. | Medium |
| deadline-linearization | Checking before a slow callback did not explicitly settle a READY transition racing timeout/closure. The summary also appeared to apply setup timeout to READY forever. | Recheck immediately at serialized publication after validation/I/O. Closure wins over late callbacks; clocks must remain trusted and monotonic. The setup timer retires after local READY; session limits continue. | High |
| replay-state-order | “Before state mutation” conflicted with authenticating and reserving the outer record before inner JSON checks. A literal implementation might undo replay acceptance on inner failure. | Distinguish MCP admission/effects from cryptographic acceptance. Inner rejection cannot restore sequence, nonce or ID state. | Medium |
| descriptor-comparison | Comparing only name/inputSchema while allowing other fields left outputSchema or extensions outside the pinned contract. A generic MCP client could interpret those fields despite this binding's fixed result contract. | Compare the entire descriptor to tool.json and close the discovery response shape. Extra semantic or descriptive members require a profile revision. | Medium |

MCP permits optional tool output schemas and metadata; therefore those fields cannot
be assumed to be semantically inert in a generic implementation. Rejecting them here
is an intentionally restricted binding, not an upstream MCP prohibition.
[Primary reference: MCP tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

## Re-review of the corrected rules

- Prepared bytes alone cannot publish READY. Both sides remain blocked during local
  send; failure discards deferred processing. Local success still does not prove
  remote receipt. Lost acknowledgements therefore leave an asymmetric but safe state.
- Timeout/close and successful callbacks serialize through one owner. Checking current
  state, deadline and session again prevents an old callback from reopening CLOSED.
- All valid authenticated RPC request attempts use one retained namespace; outer
  replay and Guard identity remain independent. A new transport cannot erase ledger
  reservations or terminal client consumption.
- The fixed `{}` marker is accepted only for the retained initialized carrier in the
  expected phase, under its exact authenticated correlation. It grants no tool result
  or authorization. Authentication does not substitute for phase validation.
- Strict discovery rejects unexpected meaning instead of allowing SDK interpretation
  to expand the proposed binding. General MCP compatibility remains explicitly limited.

These are textual design arguments, not measured runtime properties. Nine new
scenarios bring the plan to **40 NOT_RUN cases**. Document integrity tests validate
case membership, finding-to-case links, file hashes and nonpromotion; they do not
execute races, cryptography, network sends or the MCP lifecycle. No attack program
or host bypass has been produced.

## Disposition and remaining work

All five identified ambiguities are resolved **in the draft**. Verdict:
`REVISED_DRAFT_EXTERNAL_REVIEW_REQUIRED`; adoption remains `PROPOSAL_NOT_ADOPTED`.
The existing 37 lifecycle outcomes and global conformance remain unchanged.

Before adoption, obtain independent reviewer scrutiny of the barrier, acknowledgement
and timeout design, and reconcile the existing uncommitted normative baseline and its
traceability. Then define the trusted connection-owner API and add scenario unit
checks for the publication races and bounded safe runtime interoperability. An
implementation must supply bounded I/O, serialized ownership, non-bypassable mediation,
trusted keys/clocks and durable Guard state; this document supplies none of them.
HTTP mapping, generic MCP capability interoperability, formal liveness and whole-host
compromise remain outside this proposal. No claim of a hole-free protocol is made.
