# Root capture core observation

Status: bounded core API observation, not a deployed-host or full normative
conformance verdict. Protocol target: `0.10.0`. Normative source:
`sage-spec` `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. Informative host
contract: `sage-spec` `f97378cde7f29006520299c4246d2a50a429545f`.
Inspector baseline: `c8edead8784d84e3f203982066382e5849a9fb6f`.

| Subject | Exact main revision | Observable result |
| --- | --- | --- |
| Go `sage` | `77b3f072d7e715589641591674e1ca7f65146cf0` | `NewRootCapture` and `OpenCapturedClient` compare the captured ordered input commitment and root request ID before creating a Client journal. The repository's `go test ./...` and PR CI passed. |
| Rust `rs-sage-core` | `bf64338f81c45f80c3ede8c98b5fb6316e281f0b` | Public native `RootCapture::new` and `Client::open_captured` apply the same rejection before journal creation. Guard, external-import and full repository tests passed locally with the spec vector path; Linux, macOS, Windows and WASM PR CI passed. |

The independent expected commitment for one exact UTF-8 item,
`trusted root input`, is
`4dfd470e686f50c56d34a34147d753c21c7de8e012111afcd6c98f84817c8014`.
It was calculated from the 0.10.0 domain tag, big-endian item count, big-endian
byte length and item bytes with Python's standard SHA-256 implementation.
Both core tests compare their output to this fixed value. Their safe scenarios
also reject changed input and a different request ID without a journal write;
the Go entry point rejects an absent capture. These tests exercise the core
boundary, not the origin of the bytes that a host supplied.

The [host-port inspector](host-port-inspection.md) still reports
`host-capture-changed` (`EXEC-02-N01`) as `NOT_RUN`: there is no version-pinned
Agent/MCP host with independent proof of capture before model expansion,
protected original storage and complete effect/output routing. The other 12
host controls are also `NOT_RUN`. This bounded core observation therefore
does not promote `EXEC-02-N01`, any other parent case, or a protected-host
claim to `PASS`. Native Go and Rust imports are available; the Rust C ABI does
not expose this Guard path. Inspect a selected host and independently observe
its routes before changing those verdicts.

At the Inspector baseline above,
`python3 -B scripts/test_host_port_contract.py` passed all eight checker
tests. `python3 -B scripts/host_port_contract.py --spec-root <sage-spec checkout>`
returned `{"NOT_RUN":13}` for the host controls with no observation input.
The core tests use an independent expected byte commitment, but the Inspector
has not yet run the complete normative 489-parent/26-child suite against these
core revisions. That remains a separate implementation evidence task.

## Public constructor parity at the next core revisions

The [independent parity report](evidence/root-capture-parity.json) pins Go
`8c29b785e36fe8f7d7dc9e55bd9deb036df0088f` and Rust
`c99d373b772a3fb33e166fda3e07ee7ba94414f0`. Both MCP-owned root paths
retain their early capture check and now use the same captured Client opening
entry point as external native hosts. Separate, Inspector-owned Go and Rust
consumer programs build against those exact commits. Seven synthetic cases
produce identical byte commitments or rejection verdicts; the independent
Python reference checks the vector bytes, ordering and UUID/UTF-8 boundaries.

Run `python3 -B scripts/inspect_root_capture_parity.py --go-root <Go checkout>
--rust-root <Rust checkout> --output <report>` against clean, pinned sources.
`python3 -B scripts/test_root_capture_parity.py` checks the saved report and
rejects promoted host or protected-Client claims. The parity result covers the
public capture constructor only. It does not independently verify signed
intent, journal, transport, final dispatch, output release or whether a host
actually captured user input. Those remain `NOT_RUN` at this evidence level;
the 13 deployed-host controls and complete normative cases are unchanged.
