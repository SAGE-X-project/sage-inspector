# Current 0.10.0 specification inventory

Inspector now pins `sage-spec` revision
`dcdd028b5160de5e32eb1f43cf1f71eed3fc4744` in
[`reconciled-spec`](../verification/0.10.0/reconciled-spec/manifest.json).
It contains 45 requirements, 91 rule groups, 489 parent cases and 26
mandatory subscenarios. All 489 parents and 26 children remain `NOT_RUN`
against this exact revision; implementation conformance is `NOT_ESTABLISHED`.

The [earlier 489-case inventory](latest-spec-inventory.md) is preserved at
`44df132fee5925182018ce089dc82435cb353f8a`. The case graph is unchanged.
Among the source files named by that graph, only `spec/09-registry.md` changed:
the web Registry now requires exactly one parameter-free `application/json`
response `Content-Type`, rejects any `Content-Encoding`, and rejects those
fields in trailers. This resolves the prior `REG-08-N04` ambiguity. The
source and vector checks compare exact bytes against the current spec checkout;
neither the earlier excluded case nor its Go/Rust observations is silently
promoted to a result for this revision.

The [13 bounded media subconditions](../vectors/0.10.0/reconciled-spec/reg08-media.json)
are evaluated by a separate local Inspector checker. They cover two accepted
media headers and eleven rejection conditions under `REG-08-P` and
`REG-08-N04`. A successful checker run proves only the reference media
decision and source integrity. It does not observe a Go or Rust implementation,
perform TLS or HTTP fetching, validate a complete registry record, or establish
either parent case. Both parents, the web-origin deployment and core
implementation therefore remain `NOT_RUN`.

Run the revision-bound checks against the exact spec checkout:

```sh
python3 -B scripts/test_reconciled_spec_catalog.py
python3 -B scripts/test_reconciled_spec_reg08_media.py
python3 -B scripts/reconciled_spec_catalog.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-spec-inventory.json
python3 -B scripts/reconciled_spec_reg08_media.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-reg08-media.json
```

Next, add version-matched Go and Rust adapters that expose the complete web
Registry read, including trusted origin, freshness, record validation and
media/header handling. Run them against isolated local HTTP/TLS fixtures and
retain actual subject revisions and observations. Only then can Inspector
assess `REG-08-P` and `REG-08-N04` beyond the current bounded reference check.
The older 481-case and 489-case evidence directories remain historical.
