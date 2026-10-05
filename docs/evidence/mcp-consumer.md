# External native MCP consumer observation

This bounded observation pins Go
`11b1cd91691de99fdbd734db78dc6755c187b2e9`, Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb` and normative source
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. Its machine evidence is
[mcp-consumer.json](mcp-consumer.json); the independent oracle is
[inspect_mcp_consumer.py](../../scripts/inspect_mcp_consumer.py).

`ROOT_EXTERNAL_CONSUMER_BOUND` means separate Go modules and Rust executables
use public APIs for original capture, protected approval and issuance, transfer
into native MCP ownership, admission, one inert execution and consumption of its
verified signed result. Four same-core/cross-core directions succeed. Five
denials in each cross-core direction leave the receiver without reservations or
effects: policy, changed loaded component, different independent capture,
responder readiness and signing failure. Signing failure preserves the durable
issuance fence and produces no Client journal.

The consumer copies the signed intent through the new read-only Client method,
closes that Client and passes the snapshot to `OpenRootClient`/`open_root_client`
with `create=false` and the same protected path. It does not obtain invocation
authority from the snapshot or read the private journal format to extract an
intent. The receiving owner repeats current checks. The independent observer
reads journals only after shutdown to prove continuity and inspect behavior.

Inspector independently verifies the exact captured original and ordered
framing, approved policy/component commitments, Ed25519 intent and result,
single signing attempt and matching fence, no transport before transfer,
append-only continuation of the same journal, reopen delay and fresh attempt
identities, one terminal result, and exactly one durable
`RESERVED` → `EXECUTING` → `COMPLETED` sequence. Denial artifacts identify their
reached boundary; a generic connection failure does not replace a policy or
measurement observation. New issuance call IDs and nonces must be distinct
between observations. Core commits, source hashes, adapter bytes and both
dependency locks are pinned, and dirty or additional core build inputs reject
before compilation.

The loaded fixture is one inert in-memory exact-read instance, not a production
plugin loader or executable measurement. Public deterministic keys have no
production custody guarantee. Registry ready/validated/finalized states are
local fixture assertions. Logical clocks pass through the real replay
provider's startup quarantine; real wall-clock waiting is outside this run.
There is no arbitrary file access, command execution or deployed service.

`deployed_host`, independent hop execution and the independent outer handshake
oracle remain `NOT_RUN`; full conformance is `NOT_ESTABLISHED`. This report does
not select `sage-adk`, an Agent client, Registry Source deployment or a host
configuration, and does not close complete normative cases or historical gates.

Run the saved oracle and artifact rejection units:

```sh
python3 -B scripts/inspect_mcp_consumer.py
python3 -B scripts/test_mcp_consumer.py
```

Run the public consumers against clean exact core revisions, with public
dependencies already cached and the core lock copied from
`verification/0.10.0/intent-issuance/Cargo.lock` into the Rust core:

```sh
python3 -B scripts/inspect_mcp_consumer.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/mcp-consumer.json
```

The [consumer workflow](../../.github/workflows/mcp-consumer.yml) repeats the
saved oracle, rejection units, external compilation and fourteen fresh bounded
runtime observations and uploads their independent artifact. Earlier issuance
and public-host reports retain their original revisions and scope.
