# MCP owner admission model

This finite reference model explores the admission and deadline resolutions in the
[pinned consolidated proposal](mcp-consolidated-catalog.md). It does not implement a
core adapter, adopted protocol, storage engine or tool executor. The earlier setup
model and its evidence remain unchanged.

The model has one owner, one invocation and abstract ledger states ABSENT, RESERVED,
EXECUTING, COMPLETED and UNKNOWN. Final admission is an atomic symbolic transition
from RESERVED to EXECUTING. Close ordered before that transition blocks effects;
close after it cannot roll admission back. A symbolic crash while executing retains
UNKNOWN and cannot redispatch. The effect counter is an integer, not an external effect.

SETUP has a deadline of 30 model time units. READY retires that timer. A protected
operation has a fixed deadline ten units after submission, independently bounded by
session expiry at 60. Discrete clock samples include exact deadline boundaries;
clock rollback closes. Time units are abstract and do not measure production seconds.
The model never changes a protected operation back into a setup operation.

Exploration reaches a fixed point at **603 states and 11,457 transitions**. A hard
20,000-state limit fails rather than reporting truncated exploration as complete.
Retained witness traces demonstrate reserved-without-effect closure, unknown recovery,
completion after closure, and actual response publication after the setup deadline.
The last witness must end in response publication, not a later clock observation of
an already published response. Independent transition monitors also reject invalid
admission, effects without admission, lost reservations, repeated effects, terminal
outcome changes and deadline extension. Unit mutation controls exercise those monitors.

## Reproduction and scope

```sh
python3 -B scripts/test_mcp_owner_model.py
python3 -B scripts/check_mcp_owner_model.py --output /tmp/new-owner-model-report
```

Eleven tests include scenario units and a bounded CLI subprocess test that verifies
report creation and overwrite rejection. CI preserves `mcp-owner-model-<revision>`
with model source hash, Inspector revision, pinned proposal manifest and witness paths.
MODEL_CHECKED is evidence about this finite transition system only.

Authentication and current authority are assumed, with invalidation represented by
an input event. Signature algorithms, key provenance, persistent storage atomicity,
multiple owners/invocations, reconnect, distributed scheduling and actual I/O are not
verified. The model does not model cancellation of arbitrary external effects, policy
retirement transactions or a real Guard handoff. It cannot prove that two core
implementations realize the same linearization or crash behavior. Those require
future unit and bounded inert-effect runtime tests against actual APIs.

All 71 protocol cases and 37 historical lifecycle cases remain NOT_RUN; conformance
remains NOT_ESTABLISHED and external review false. No cryptographic scenario is marked
PASS by this model. Normative adoption and concrete API implementation remain pending.
