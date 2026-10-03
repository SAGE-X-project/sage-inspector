# Guard policy after protected MCP delivery

The [three-case suite](../vectors/0.10.0/guard-session-policy010.json)
observes the boundary between authenticated MCP request delivery and Guard
admission on `sage-spec` revision `fa006fd917ad365eb554a27f4178301cd66e2379`.
It covers the protected request handoff in TRANSPORT-01/02/03 and the MCP
integration contract in EXEC-08. The signed intent, RPC ID, and exact request
bytes remain fixed while the trusted local policy decision changes.

At Go `fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`, local execution passed
**12/12 cases**: allow, deny, and policy revocation after a valid protected
request was opened, across Go/Go, Go/Rust, Rust/Go, and Rust/Rust. The runner
independently verifies the handshake, outer request, and inner intent Ed25519
signatures using fixed public test keys. The receiver must expose the exact
RPC bytes and make one transport replay reservation before Guard dispatch.
The allowed case produces one inert effect and the expected Guard journal
states. Both denied cases produce no Guard admission, effect, signed reply, or
Guard journal row. A denied request's transport replay reservation remains
observable; it is not a Guard authorization.

The companion unit test checks the expected case set, exact positive and
negative observations, and that policy revocation changes only the local
policy input. CI builds both Guard and session adapters from the pinned core
revisions, runs the unit and runtime checks, and retains the report and raw
local process transcript.

```sh
python3 scripts/test_guard_session_policy010_unit.py
python3 scripts/test_guard_session_policy010.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --spec-root /path/to/sage-spec \
  --go-session /path/to/go-session-adapter \
  --rust-session /path/to/rust-session-adapter \
  --go-guard /path/to/go-guard-adapter \
  --rust-guard /path/to/rust-guard-adapter \
  --output /new/output/guard-session-policy
```

The observation uses controlled local processes and an inert effect sink.
It does not establish that a deployed Agent host routes every plugin, MCP,
file, network, or subprocess effect through Guard. Live Registry resolution,
host integration, and full protocol conformance remain `NOT_RUN` or
`NOT_ESTABLISHED` as stated in the report.
