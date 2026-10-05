# Public native MCP host and root TCP observation

Go `6a99b558a18d9c33ae9a07ce2ffa75af495661d0` and Rust
`cc83fba11d0e155d31af67dbdd840c9ab8cb0d9e` now expose native protected MCP
host assembly. The APIs construct the owner monitor, execution admission,
fixed workers, Client pool and authenticated carriage before peer input.
Endpoint construction follows connection reservation; actual readiness precedes
the initialized acknowledgement. Callback-scoped connections expose no raw
transport, READY setter or reservation/worker token. Incomplete shutdown
retains quotas and the exclusive ledger lock until actual cleanup ends.

The [machine report](public-mcp-host.json) pins exact merged sources and records
four independent compiler builds: a public external Go/Rust consumer builds,
and a separate compiler check rejects private connection state in each core.
The consumers are inert compilation probes, not complete integrations.
Inspector also builds the native core test binaries and runs these bounded,
separate-process localhost exchanges using only the public host methods:

| Client → server | Observation |
| --- | --- |
| Go → Go | Authenticated setup, root binding, one inert effect, signed terminal consumption |
| Rust → Rust | Authenticated setup, root binding, one inert effect, signed terminal consumption |
| Go → Rust | Same root operation and exact signed result across cores |
| Rust → Go | Same root operation and exact signed result across cores |

An independent Python cryptography oracle checks the canonical signed intent,
Ed25519 proof, ordered original-input framing, local policy and component
commitments, exact arguments, peer/key roles, expiry and signed result binding.
It checks fresh outer attempt IDs, one-second retry cadence, consumed terminal
identity and the receiver's exact RESERVED→EXECUTING→COMPLETED ledger history.
The saved terminal must equal the receiver's signed stored result; the recorded
inert effect count must be exactly one. The fixture reads no external file:
its sole exact operation returns `{"ok":true}`.

The status is `ROOT_MCP_TCP_INTEROP`. Setup and outer protection are exercised
by the cores; this report does not independently verify captured outer
handshake transcripts. Providers use local public-key/registry fixtures and
simulated clocks. The Go endpoint uses a durable replay fixture with both UTC
and monotonic startup quarantine advanced before traffic; the Rust endpoint
uses its existing in-memory test replay provider. This run therefore makes no
cross-core durable replay recovery or authoritative registry claim.

Native unit and safe runtime suites additionally cover changed originals,
failed readiness, invalid configuration, bounded blocked providers and retained
capacity/ledger ownership during incomplete shutdown. Go tests also confirm
that copied connections are unusable after the callback. Those denial schedules
are core tests, separate from the four independent positive observations.
The twelve Inspector units reject corrupted evidence, valid signatures bound
to the wrong original, type substitution, missing directions and scope promotion.
They do not execute an attack or host bypass.

The protected issuer and MCP Client opening APIs remain separate: this report
does not claim an integrated issuer-to-consumer binding. Independent hop
execution is `NOT_RUN`; all thirteen deployed-host controls remain `NOT_RUN`;
full conformance is `NOT_ESTABLISHED`. Actual capture timing, protected key
custody, stable journal identities, immutable loaded components, alternate-route
mediation and authoritative deployments remain host responsibilities. The next
approved work is external consumer binding of those services, followed by
selection and inspection of an exact host executable. No demo stage is started.

The normative source remains `sage-spec`
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`; no 0.10.0 wire or RFC rule changed.
The historical [public API audit](host-public-api.md) and
[issuer observations](intent-issuance.md) retain their original pins and verdicts.

## Reproduction

Use clean checkouts at the two merged revisions above. Fetch public dependencies
first, using Go 1.26.8, Rust 1.88.0 and Python `cryptography==50.0.0`.
Rust ignores its library lock; copy Inspector's pinned
[core dependency lock](../../verification/0.10.0/intent-issuance/Cargo.lock)
into that checkout before fetching. Both native compilation and the external Rust consumer use offline, locked
resolution. The separate [consumer dependency lock](../../verification/0.10.0/public-mcp-host/Cargo.lock)
is also hashed and checked before compilation:

```sh
cp verification/0.10.0/intent-issuance/Cargo.lock /path/to/rs-sage-core/Cargo.lock
cargo fetch --locked --manifest-path /path/to/rs-sage-core/Cargo.toml
RUSTUP_TOOLCHAIN=1.88.0 python3 -B scripts/inspect_public_mcp_host.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/public-mcp-host.json
python3 -B scripts/inspect_public_mcp_host.py --report /tmp/public-mcp-host.json
python3 -B scripts/test_public_mcp_host.py
```

Fixture inner call/nonce identities are fixed in fresh isolated storage per run;
outer IDs and cryptographic handshake randomness are fresh. Inspector checks
bindings and signatures instead of comparing random artifacts. Without core
paths, the script validates saved evidence only and executes no native process.
Dedicated CI reruns public compilation and all four native exchanges against
exact merged revisions, retaining its fresh report as an artifact.
