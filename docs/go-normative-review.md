# Go normative implementation review — SAGE 0.10.0

This review compares Go revision `2322b2aa4b13ed41b2c5232a1d7382003ebee0e1`
with the 26 mandatory child schedules adopted by `sage-spec` revision
`520e5ed9a896ff8ba8ade776484f41084957aaa2`. It does not change the protocol,
promote the historical catalogue, or establish conformance.

## Result

| Classification | Count | Meaning |
|---|---:|---|
| DIRECT | 16 | A named Go test directly observes the required ordering and effects |
| PARTIAL | 5 | A related test exists but does not isolate every required identity or ordering |
| MISSING | 5 | No exact Go schedule exists |

The existing parent-case overlay remains useful, but it is insufficient to close the
adopted binding plan because the mandatory schedules are normative children of those
parents. Similar behavior is not promoted to direct evidence.

## Required Go closure

The next Go change must close these ten items without altering the normative design:

1. distinguish policy generation from generic configuration replacement;
2. observe authority state acquired at or before operation start;
3. force the final capacity race after preparation;
4. inject a bounded final queue insertion failure;
5. fail UNKNOWN persistence after a successful fence;
6. fail recovery conversion from EXECUTING to UNKNOWN;
7. distinguish policy retirement before claim;
8. distinguish policy retirement after claim and retain the pinned policy instance;
9. order scheduler cancellation and claim in both directions;
10. reach sequence 999 and reject sequence 1000 through an authenticated MCP session.

Only safe local state, inert executors and bounded processes are used. No host-bypass
or attack-capable reproduction program is required. After the Go tests pass under the
race detector, Inspector will reclassify each child from PARTIAL or MISSING using exact
test names and captured results. Rust review remains the following separate step.

