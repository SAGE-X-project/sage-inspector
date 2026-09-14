# Live exchange and host inspection — 0.10.0

This delivery runs real Go→Rust and Rust→Go record exchanges, and prepares an
executable contract for eight host bypass probes. INS-11 remains in progress:
full 0.10.0 handshake/HTTP/WS exchange, replay/lifecycle and actual host isolation
still require core and host bindings. No host was selected or executed.

## Remaining work

| Item | State | Completion evidence still needed |
|---|---|---|
| Legacy record API exchange in both directions | Executed | Rerun when core implementations change |
| Transcript-bound record API | UNSUPPORTED | A real API accepting the transcript binding |
| Full HPKE confirmation and HTTP/WS request/response exchange | NOT_RUN | Two complete 0.10.0 endpoints and observed wire bytes |
| Cross-core replay and explicit close | Executed | [36 actions and four fresh-record controls](replay-inspection.md) passed; [bounded concurrent receive checks](concurrent-inspection.md) also passed; expiry, recovery and close races remain pending |
| Host hook/direct-call/process/file/network/key access probes | Prepared; 8 NOT_RUN | Pinned host executable/configuration and a trusted external witness |
| Deployment-level conformance review | NOT_ESTABLISHED | Complete relevant bindings, passing positive controls and scoped isolation evidence |

These are the remaining parts of INS-11. Core feature implementation, SDKs, MCP
services, demos and repository separation remain separate projects.

## Actual core exchange

```sh
go build -o /tmp/sage-exchange ./cmd/sage-exchange
/tmp/sage-exchange \
  -go-adapter /absolute/path/to/go-adapter \
  -rust-adapter /absolute/path/to/rust-adapter \
  -go-revision ACTUAL_GO_COMMIT \
  -rust-revision ACTUAL_RUST_COMMIT > /tmp/exchange.json
```

Build the adapters using their existing nested Go/Cargo projects and the pinned
core source lock. The new `sage.session.record.export` adapter operation invokes
the real legacy core encryption API and returns its exact bytes, length and digest.
Inspector forwards these bytes to the other core; no expected ciphertext substitutes
for the sender. It runs both c2s and s2c roles in both implementation directions.

For each exchange, observe production, intact recovery, altered ciphertext, AAD,
seed, direction, session ID and transcript-bound opening. All inputs use a public
fixed test seed, a 32-byte test plaintext and test-only identifiers. Five negative
checks change only the declared field. Transcript checking uses the separate
`sage.session.record.open.bound` operation because the existing record API has no
transcript argument; both adapters correctly report it UNSUPPORTED. Inspector does
not implement that missing binding or silently discard the transcript and claim a
core failure. The existing `open` operation remains an explicitly legacy projection.

At the pinned core revisions, all four exchanges recover the sender's plaintext.
The final evidence has **28 PASS, 0 FAIL, 4 UNSUPPORTED**: four producer observations,
four intact recoveries, twenty mutation rejections and four missing transcript
bindings. The aggregate is INCOMPLETE. A fresh receiving process is used for every
check, so that report alone does not test replay rejection. The separate [stateful run](replay-inspection.md) now covers replay and explicit close. Matching legacy implementations can
share a specification deviation; these results do not replace the frozen normative
vectors or establish full 0.10.0 interoperability.

The process transport supplies time limits, bounded stdout/stderr, correlation
checks and executable hash checks. Producer errors never become receiver rejection
passes. Missing producer bytes leave the receiver checks NOT_RUN. Negative results
retain their positive-control status, including failed controls. The CLI exits 0
for listed exchange passes, 1 for observed failure, 2 for configuration failure,
and 3 for incomplete support; whole-protocol conformance is always NOT_ESTABLISHED.

## Host adapter contract

```sh
# No host configured: writes eight NOT_RUN entries and exits 3.
python3 scripts/inspect_host.py --output-dir /tmp/host-readiness

# With a separately implemented, explicitly configured host adapter:
python3 scripts/inspect_host.py --runner /absolute/path/to/sage-scenario \
  --adapter /absolute/path/to/host-adapter --binding /absolute/path/to/binding.json \
  --output-dir /tmp/host-run
```

The binding JSON declares `name`, `version`, `revision`, `isolation`,
`witness_boundary`, `host_executable`, `host_configuration` and `witness_executable`.
The last three fields are absolute local file paths. Their hashes and the adapter,
runner and declaration hashes are recorded. The adapter must already launch the
specified host/configuration and connect the specified external witness; a declaration
and matching hashes alone do not prove that this connection or isolation exists.
The operator reviews it before making any deployment claim. No fixture selects
an executable, production resource, real signing key or arbitrary shell command.

Each fixture runs setup, an authorized positive probe, an unauthorized attempt,
an external observation after quiescence (including descendants and delayed effects),
and another authorized probe after restoring the injected fault. The authorized
probe writes a disposable protected sentinel, contacts a local test sink and makes
a child perform a monitored protected effect. The witness counts only these defined
protected resources, not every operating-system file access or process creation.

Attacks cover missing/timed-out hooks, direct tool calls, child-process access,
file/network access, plugin-side verifier replacement and key/oracle access.
The trusted witness measures dispatch, protected file/network/child effects,
key disclosures and unauthorized signatures. Its measurements must be outside the
plugin's compromised boundary. A plugin's self-reported counters cannot establish
host isolation. Failure to obtain trustworthy observations is an error or unsupported
binding; it is never evidence of zero effects. The supplied schema2 fixtures and
synthetic runner tests prove the test contract only.

## Evidence and CI

- `docs/evidence/deployment/exchange.json`: fresh live core observations, exact
  requests/output bytes, executable identities and positive-control relationships.
- `docs/evidence/deployment/host/summary.json`: eight NOT_RUN host scenarios;
  observed effects are null.
- `docs/evidence/deployment/provenance.json`: pinned artifacts, core lock and exact
  Inspector source hashes for the working-tree build used in this run.
- The integrated report links this deployment evidence separately from the existing
  525 primitive cases and 97 prepared lifecycle scenarios per core. The new host
  inventory adds eight scenarios (40 steps); it does not promote any of the 386
  planned normative cases to PASS.

Run `python3 scripts/check_deployment_evidence.py` and
`python3 scripts/test_deployment_inspection.py` to check membership, wire forwarding,
mutations, hashes, false passes and host readiness. CI runs these alongside Go
exchange/host contract tests and preserves the raw artifacts. Fresh core builds
and actual host execution are distinct from CI validation of archived evidence.

추가 진단: [수신·종료 경합](close-race-inspection.md)은 Go DATA_RACE 실패와 Rust 직접 병행 종료 미지원을 별도 기록한다. 원시 프로세스 오류와 stderr를 검증하며, 기존 primitive/계획 사례 통과 수에는 합산하지 않는다.
