# Demo comparison verdict

**Verdict: `BOUNDED_DEMO_COMPARISON`.** This closes stage 6 of the
[approved program sequence](https://github.com/SAGE-X-project/sage-spec/blob/85fee1830b2bc0d2420557df40796ae83073de12/architecture/program-sequence.md):
a runnable demo runs one agent workload with and without SAGE protection,
injects the same faults into both, and measures what each run executed. It is
not a deployment, Registry, measurement or conformance verdict, and a defended
fault in the demo is not a universal security claim. Everything the
[core and host integration verdict](core-host-integration-verdict.md) carried
forward stays as it is.

The normative source remains `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`.
Revisions at this verdict: `sage-demo`
`c7e64adf486f394b2c9bdbefc4d95a83a742a831`, ADK module
`v0.0.0-20261010085535-c7890e1ba443` and Go core module
`v1.5.3-0.20261009164347-40809355bd4d`, the revisions of the integration
verdict.

## What was observed

The [observer](../scripts/inspect_demo_comparison.py) requires a clean
checkout of the pinned demo, builds it with Go 1.26.8 on a GitHub
`ubuntu-24.04-arm` runner and runs `demo setup` and then every scenario in both
modes. In each run the tool host, the agent and, in SAGE mode, one signer per
identity are separate processes under one account; the run process is the
relay. The saved observation is
[demo-comparison.json](evidence/demo-comparison.json).

The observer does not trust the demo's verdict fields. For each run it checks
its own expectation of the ledger, the results the agent accepted, the frames
the relay forwarded and the frames the fault changed. For example, it requires
the changed SAGE request to be the call frame after the tool host answered
every frame before it, so a refusal caused by something other than the fault
does not count. The [refusal units](../scripts/test_demo_comparison.py) change
the saved report and confirm that weaker outcomes are refused.

The workload is a scripted agent asking for one mock transfer of 10 DEMO to a
fixed recipient. The ledger file the tool host writes is the effect the
comparison inspects.

| Scenario | Fault | Without SAGE | With SAGE |
| --- | --- | --- | --- |
| `normal` | None. | 10 calls, 10 transfers, each result accepted. | Same. |
| `tamper-args` | The relay changes the request that carries the call. | 990 transferred to another recipient. | Refused; no transfer. |
| `replay` | The relay resends a completed connection. | The transfer ran twice. | The resent connection got no answer; one transfer. |
| `unapproved` | The agent asks for a transfer outside the approved one. | It ran. | Refused before any request frame left the agent. |
| `forge-result` | The relay changes the result on its way back. | The agent accepted a result matching no ledger state. | The transfer ran once; the agent refused the changed result. |

Measured costs in this observation: the normal call took a median of 1.11 ms
without SAGE and 1158.53 ms with SAGE over 10 calls each, and setup took
366.3 s, of which 365.1 s waited out the 360-second replay quarantine of new
host state. The ADK caller polls for the result every 1.1 seconds, which puts
a floor under each SAGE call; the rest of the call time was not broken down.

## Exit evidence

The program sequence asks stage 6 for comparable workflows with the same
workload, measured defended behavior and residual risks, and no universal
security claim.

**Comparable workflows with the same workload.** Both modes send the same
transfer request through the same relay with the same fault applied at the
same point of the connection: the frame that carries the call or the result.
Because the SAGE exchange is encrypted and signed, the relay changes bytes of
that frame instead of rewriting fields. Both modes use the same ledger, tool
and harm check.

**Measured defended behavior.** Each defended fault above is measured by its
effect in the ledger, the agent's outcome and the relay frames, not by an
error message. The SAGE host returns one error code for every refusal, so the
observation does not claim which check refused a call; it shows how far the
connection got.

**Residual risks.** The demo's
[design](https://github.com/SAGE-X-project/sage-demo/blob/c7e64adf486f394b2c9bdbefc4d95a83a742a831/docs/design.md)
and README state what SAGE does not defend here. A compromised agent host can
still issue the approved operation. A compromised tool host can act within
its session, and the signer's per-handshake X25519 shared value lets it derive
that session's secrets. An operator approval key compromise lets an attacker
approve new operations. The relay can always drop or delay traffic. The
forge-result run shows that a transfer can run while the agent cannot confirm
it.

**No universal security claim.** Every SAGE report states the synthetic
Registry Source, the accept-all measurement, the single account and kernel
and the single refusal error code, and the observation scope records
`universal_security_claim: NONE` and `full_conformance: NOT_ESTABLISHED`.

## Carried forward

| Item | Status | Where it continues |
| --- | --- | --- |
| IdentityAndReadiness and MeasuredComponent | `NOT_BOUND`, as in the integration verdict. | Stage 8 for the Registry Source; a selected Local provider for measurement. |
| Account separation in the demo | One account and one kernel. The ADK qualification separates accounts; the demo does not. | A separate-account Linux demo run, a later addition in the demo design. |
| Model-facing path | A scripted agent; prompt injection and model tool choice are outside the demo. | Not scheduled. |
| Refusal stage | Not distinguishable from the host error. | An ADK change that exposes refusal causes, if selected. |
| Deployed host controls and full conformance | `NOT_RUN` and `NOT_ESTABLISHED`. | Later deployment stages. |

## What this permits

Stage 7 may extend the specification and Inspector for the intended A2A and
DID interoperability; stage 9 updates this demo to the adopted identity and
contract model and repeats these measurements with exact revisions.

## Evidence nature

The saved report is a review record of one CI runner, not a signed
attestation. A later normative change, a new demo revision or new core
revisions require a new observation before any claim about them.
