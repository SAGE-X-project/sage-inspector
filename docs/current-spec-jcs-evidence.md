# Current-spec duplicate-key observation

The pinned `sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`
requires JCS-01 to reject duplicate JSON member names after parsing escapes.
Inspector fixture `JCS-01-N01` sends the raw UTF-8 bytes for
`{"a":1,"a":2}` to the Go and Rust core JCS adapters. Its expectation was
stored before either core ran and was not sent to the adapters. The fixture
is **partial** because the primitive adapters cannot observe protected
dispatch effects or the complete receiving schema.

| Subject | Source revision | Primitive result | Inspector case result |
| --- | --- | --- | --- |
| Go `sage` | `49379baadc6baec9ca8b4bb7d15bf43d65144bd7` | ACCEPT; canonical bytes encode `{"a":2}` | `FAIL` |
| Rust `rs-sage-core` | `ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396` | REJECT | `PARTIAL` |

The [preserved raw and assessed reports](evidence/current-spec/jcs-duplicate/)
pin the spec, Inspector runner, fixture, adapter, core revision and executable
hashes. `scripts/check_current_spec_jcs_evidence.py` rechecks the file hashes
and recomputes the verdicts. Neither result establishes full JCS-01 or overall
0.10.0 conformance. The Go mismatch is a core implementation finding, not a
reason for Inspector to accept duplicate input.

Both adapters were built from temporary copies, with their local dependency
paths pointing to the listed core checkouts. The Go build used a temporary
`GOCACHE`; the Rust build used `--offline --locked --bin
sage-inspector-rust-adapter` and a temporary target directory. Building all
Rust adapter binaries exposed an unrelated `guard_client010` initializer
error (`expected_issuer` and `expected_recipient` missing); the targeted
primitive binary built and ran. The Go core checkout had an untracked
`contracts/` directory; this JCS adapter imports the core JCS package and
did not build from that directory. No core source was edited for this run.
