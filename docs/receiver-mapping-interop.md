# Receiver mapping native MCP interop

This observation runs native protected MCP exchanges in which the receiver does
not hold the caller's original request. It pins Go core
`e6c40f4bddb457702810c1058eaf863bd31293ec` and Rust core
`4f691b3526063e74c4408bef9abfa998cbaf4c0d`, both after the receiver policy
mapping changes (SAGE-X-project/sage#430, SAGE-X-project/rs-sage-core#123) and
their process helper updates. The frozen SAGE 0.10.0 source remains
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. The earlier
[public MCP host observation](evidence/public-mcp-host.md) and its pinned
revisions are unchanged.

## What runs

The [observer](../scripts/inspect_receiver_mapping_interop.py) builds the native
Go and Rust test binaries from clean pinned checkouts and the
[pinned Rust lock](../verification/0.10.0/receiver-mapping-interop/Cargo.lock),
then runs four separate-process loopback exchanges: Go→Go, Rust→Rust, Go→Rust and
Rust→Go. Each server process sets `SAGE_MCP_PUBLIC_RECEIVER_MAPPING=1`. The Go
server verifies through `NewReceiverPolicy` and a fixture mapping and replaces its
fixture original with a wrong value; the Rust server verifies through
`ReceiverPolicy`, whose bindings never supply an original. Clients are the
unchanged root Clients.

The same independent Python oracle as the public MCP host observation checks
each exchange: the canonical signed intent and its original, policy and manifest
commitments, fresh outer attempts and retry cadence, one terminal consumption,
the independently checked signed result and the receiver's exact
RESERVED→EXECUTING→COMPLETED ledger with exactly one inert effect.

Before this observation, separate local runs showed that a Go server with the
wrong original but without the receiver policy fails the same exchange, so
success comes from the mapping path. That control is not part of the saved report.

## Scope and limits

`RECEIVER_MAPPING_MCP_TCP_INTEROP` covers these four exchanges only. Registry,
clocks, replay and keys are local test fixtures, the effect is an inert exact
read, and the outer handshake transcript is not independently checked. No host
deployment is selected; deployed host controls remain `NOT_RUN` and full
conformance remains `NOT_ESTABLISHED`.

## Reproduction

```sh
python3 -B scripts/inspect_receiver_mapping_interop.py
python3 -B scripts/test_receiver_mapping_interop.py
python3 -B scripts/inspect_receiver_mapping_interop.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/new-receiver-mapping-interop.json
```

A fresh run needs both pinned clean checkouts, Go 1.26.8, Rust 1.88.0 and the
pinned lock copied into the Rust checkout, as the
[workflow](../.github/workflows/receiver-mapping-interop.yml) does. The saved
report comes from that workflow's run 37870353263.
