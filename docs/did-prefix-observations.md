# DID and DID URL prefix observations

The six-case [suite](../vectors/0.10.0/did-prefix.json) is derived from
`sage-spec` revision `44df132fee5925182018ce089dc82435cb353f8a`,
`spec/06-did-sage.md` rule ID-01 and cases `msca-did-prefix-case` and
`msca-did-url-prefix-case`. It includes a canonical web DID or DID URL as a
positive control beside uppercase scheme and method variants. The suite
checks only these primitive inputs; it cannot establish either complete
normative parent case or registry authority.

| Subject | Canonical DID | Uppercase DID scheme/method | DID URL cases | Suite |
| --- | --- | --- | --- | --- |
| Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7` | FAIL: rejected | 2 PASS: rejected | 3 UNSUPPORTED | FAIL |
| Rust `ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396` | FAIL: rejected | 2 PASS: rejected | 3 UNSUPPORTED | FAIL |

The [Go report](evidence/did-prefix-go.json) and
[Rust report](evidence/did-prefix-rust.json) preserve exact inputs,
expectations, outputs, source and executable hashes. Both core adapters use
their existing DID parser. Their uppercase rejection is real, but the same
parser also rejects the canonical 0.10.0 web DID. That false rejection blocks
the DID parent case. Neither adapter exposes `sage.did-url.validate`; all
three URL inputs are explicitly `UNSUPPORTED`, including the positive
control. These results do not change the [489-parent latest-spec evidence
inventory](latest-spec-inventory.md): the parent cases remain `NOT_RUN` until
complete version-matched cases execute. A partial primitive observation cannot
be promoted to parent `PASS`.

To check the preserved suite and reports against the pinned source revision:

```sh
python3 -B scripts/generate_did_prefix_suite.py --spec-root ../sage-spec
python3 -B scripts/test_did_prefix_suite.py
python3 -B scripts/test_did_prefix_reports.py
python3 -B scripts/check_did_prefix_reports.py
```

The report auditor requires the observed `FAIL` and `UNSUPPORTED` outcomes;
it rejects a rewritten success report. A new runtime observation requires
rebuilding `cmd/sage-conformance` and both adapters against the named core
revisions and recording new reports. The next implementation step is a
0.10.0 DID and key-URL API in each core with canonical positive controls,
exact prefix rejection and full peer/key binding, followed by complete
Inspector parent-case execution.
