# Remaining Execution Guard host boundaries

The current 0.10.0 inventory has ten host-dependent EXEC parent cases after
the bounded Go/Rust core observations. Inspector now binds 15 typed runtime
probes, including five EXEC-01 isolation cases, and 15 deployment-review
fixtures across EXEC and CST-02. Each still requires
evidence from a versioned Agent or executor host integration. A core method
that rejects a supplied fixture cannot prove that every host route invokes it.
These cases remain `NOT_RUN` in the current-spec report; the inert unit traces
are not promoted to implementation conformance.

| Case | Required observed boundary |
| --- | --- |
| `EXEC-02-N02` | Capture a model proposal, the Client's independent authorization decision, the exact signed intent, and zero protected dispatch when the proposal is unchecked. |
| `EXEC-04-N04` | Hold a verified call at the final dispatch gate, change the proposed arguments before admission, and observe refusal without a protected effect. The observed component instance and exact admitted bytes must be recorded. |
| `EXEC-05-N05` | Cancel after protected queue or external-effect commitment; record the durable state and externally observed outcome. The host must not report rollback or definite failure when the result is uncertain. |
| `EXEC-06-N01` | Show that plugin or model writes cannot update the approved baseline. Record the authenticated administrative update path and old/new digest decisions. |
| `EXEC-06-N02` | Inspect the loaded artifact's path and file type with the actual loader; symbolic links must be rejected before load. |
| `EXEC-06-N04` | Couple measured bytes to the very artifact instance loaded by the worker. A check of one path followed by reopening changed bytes is insufficient. |
| `EXEC-06-N05` | Review the host's claims and trust source: a peer-provided hash must not be accepted as local measurement or remote attestation. |
| `EXEC-08-N01` | Exercise a protected request with model-visible verification omitted; the internal gate must still run and deny if no trusted verdict exists. |
| `EXEC-08-N02` | Review every model/plugin-accessible signing surface and its caller authentication. No unrestricted signing operation may accept arbitrary intent bytes. |
| `EXEC-08-N03` | Bound a trusted gate call, then inject timeout/disconnect through the host adapter. Observe denial and zero protected effect. |

The [host fixture suite](../vectors/0.10.0/exec-host-contracts.json) and
`scripts/current_spec_host_trace_bridge.py` define a bounded observation
interface. A real host adapter receives only the case ID and trigger and must
return typed facts plus separately observed and subject-reported effect counts.
The bridge derives a verdict and never accepts a subject-reported PASS. The
unit tests vary each case's decisive fact and check that contradictory effect
counts fail. This prepares inspection; no host adapter has been run.

The Inspector must accept version-pinned host observations with the exact
request and component identity, ordered gate events, durable journal state,
actual effect counter, and evidence of route coverage. Deployment reviews must
name the host build, loader, policy/baseline authority, and all callable tool
paths. For cases involving mutation, cancellation, or timeout, the unit
scenario may use an inert local sink; do not create an external attack tool.
An absent host adapter or absent route inventory remains `NOT_RUN` or
`UNSUPPORTED`, not `PASS`.

The fixed inspection-contract order has been followed: EXEC/CST/hop,
`PROC-01..03`, `EVIDENCE-01`, `MSET-01..08`, `MOWN-01..05` and the 26 mandatory
`MOWN-06` children, then the 51 earlier skipped parents. Every required track
now has a pinned partial contract. The ten host boundaries above still need
versioned subject observations before any implementation verdict is possible.
