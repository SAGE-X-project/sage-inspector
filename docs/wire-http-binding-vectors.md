# Signed wire and HTTP binding observations

Inspector imports the exact [sage-spec `0.10.0` wire/HTTP reference fixture](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/verification/vectors/wire-http-binding-0.10.0.json),
SHA-256 `17de2b6ca0eaf71cb7e1ad4c569b2a7b0e235f1ba9992c05fcacde86fbcf6a63`.
The [local source copy](../vectors/0.10.0/wire-http-binding-source.json) and
[six-case suite](../vectors/0.10.0/wire-http-binding.json) are byte-checked
against that pinned source in CI. The suite passes the fixed request and response
HTTP bytes unchanged to the existing adapter contract. It asks the cores for
two RFC 9421 signature bases, two content digests, and two complete
`sage.http.verify` boundary decisions. The latter require a version-matched
core entry point; a primitive match cannot substitute for them.

| Subject revision | HTTP bases | Digests | HTTP/wire boundary | Suite result |
| --- | --- | --- | --- | --- |
| Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7` | 2 FAIL | 2 PASS | 2 UNSUPPORTED | FAIL |
| Rust `ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396` | 2 PASS | 2 PASS | 2 UNSUPPORTED | INCOMPLETE |

The [Go report](evidence/wire-http-binding-go.json) and
[Rust report](evidence/wire-http-binding-rust.json) pin the suite hash, exact
inputs, subject revisions and adapter executable hashes. Both Go base
differences are specific: the reconstructed `@signature-params` line omits
`;tag="sage-0.10.0"` while all preceding bytes match. Rust reconstructs both
bases exactly. This is a measured Go implementation gap at the named revision,
not a reason to change the fixed expectation. Both adapters explicitly return
`UNSUPPORTED` for the full receive boundary, so neither subject has passed
the inner/outer signature, key status, replay and dispatch transaction. The
[report auditor](../scripts/check_wire_http_binding_reports.py) rejects
relabeling the Go failures or either unsupported boundary as PASS.

This fixture carries an initiation-shaped payload and a signed `unavailable`
response. It does not perform HPKE SetupBase, establish a session, prove a
registry record or test application effects. Its fixed 2024 reference time
is injected only through the test control. The existing Inspector
[current-spec inventory](current-spec-coverage.md) is pinned to the older
`5bcf511e604579afa63f434013447f44b6858828` revision with 481 parents.
The imported sage-spec revision has 489 parents: eight new `msca-*` cases.
They are listed in the separate [latest specification inventory](latest-spec-inventory.md)
with partial source-bound host contracts. No `msca-*` parent is marked PASS
by this fixture or its contracts.

To repeat the checks from a checkout beside the pinned sage-spec revision:

```sh
python3 -B scripts/generate_wire_http_binding_suite.py --spec-root ../sage-spec
python3 -B scripts/test_wire_http_binding_suite.py
python3 -B scripts/check_wire_http_binding_reports.py
go test ./pkg/conformance
```

Rebuild `cmd/sage-conformance` and the two adapters against the stated core
revisions to refresh runtime reports. Use a new report path for each run;
preserved reports describe these exact revisions. Full HTTP boundary inspection
still requires each core to expose a trusted-clock, key-status and replay-aware
entry point.
