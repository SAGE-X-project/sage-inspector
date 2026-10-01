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
cover two accepted media headers and eleven rejection conditions under
`REG-08-P` and `REG-08-N04`. The reference checker validates their source and
expected decisions. A separate runtime observer builds the pinned Go core at
`1dc22e71673bfa40cc63b342a2e66fdfee2f3ee2` and Rust core at
`79fe9bbcd7a417a523d77a267c8420cf4f506746`, runs each case against
both executables, and records the actual verdicts, source revisions and binary
hashes. Inspector also pins the Rust dependency resolution in
[`registry-media-Cargo.lock`](../verification/0.10.0/reconciled-spec/registry-media-Cargo.lock)
because the Rust library does not track a lockfile. Each core matched all 13
media decisions in the local run. The CI report retains the same bounded
evidence for its own build.

The [20 bounded envelope subconditions](../vectors/0.10.0/reconciled-spec/reg08-envelope.json)
now exercise the 69632-byte response limit, closed JSON wrapper, duplicate
members, Unicode and number parsing, and the five-second issued/expires
lifetime. Inspector builds Go core revision
`628d36cce452762abb0c9e4a0e10b35d4a059529` and Rust core revision
`7658959e34f69ad100d085a0a04702dab8d8c2e4` with the pinned Rust
dependency lock. Each matched all 20 expected decisions in a local runtime
check; CI preserves its own per-case report and executable hashes. Accepted
envelopes in these fixtures deliberately contain an empty `record` object.
They do not imply that a usable Registry record exists.

The 13 media observations cover only the response media decision. Neither executable
fetches an HTTP response, verifies TLS or web-origin authority, parses a
complete Registry record, or establishes `REG-08-P` or `REG-08-N04`. Both
parent cases and the remaining 487 parent cases remain `NOT_RUN`; complete
implementation conformance remains `NOT_ESTABLISHED`.
The envelope observations have the same limit: they do not check the nested
record's separate 65536-byte bound, schema, DID, key proofs, or authority.

The [26 bounded record-shape subconditions](../vectors/0.10.0/reconciled-spec/reg08-record-shape.json)
now check the exact encoded 65536-byte record bound, closed fields, web DID
binding, key and service structure, and version. Inspector builds the pinned
Go core at `19c39080cc78918a307bc9008834874558bdd4c8` and Rust core at
`d13b4dff709a90428da4272ce45c1b1df48914b3`, then records each actual
decision and executable hash. Both matched 26/26 cases in the local runtime
check; CI preserves its own report. The positive fixtures use placeholder public
bytes and proof values solely for structural checks. A shape acceptance is
not a valid signature, trusted HTTPS origin, authenticated controller, or
complete Registry observation. All REG-08 parent cases remain `NOT_RUN` and
conformance remains `NOT_ESTABLISHED`.

The [16 bounded proof subconditions](../vectors/0.10.0/reconciled-spec/reg08-record-proofs.json)
exercise REG-04 signatures over the exact web Registry challenge for Ed25519,
P-256, and secp256k1, plus X25519 KEM endorsement. Inspector builds Go core
`3c09b4a497f4086e11ac5fa529ea933df32d7208` and Rust core
`061c2e489e3f388bcee113382167285e17b72064`. The fixed input includes
independently generated Ed25519, X25519, and P-256 material; every actual
decision and executable hash is retained. The Rust build uses the pinned
[`registry-proofs-Cargo.lock`](../verification/0.10.0/reconciled-spec/registry-proofs-Cargo.lock).
Both cores matched 16/16 expected decisions in the local runtime check; CI
preserves its own report. A successful proof check establishes
only these cryptographic subconditions. In particular, a revoked or expired
historical KEM signer still needs authenticated evidence that it was authorized
when the endorsement was added. HTTPS origin, controller and mutation history,
all REG-08 parent cases, and complete conformance remain `NOT_RUN` or
`NOT_ESTABLISHED` as appropriate.

The [15 bounded origin-policy subconditions](../vectors/0.10.0/reconciled-spec/reg08-origin-policy.json)
check exact web DID lookup URL construction against a locally configured HTTPS
origin allowlist, non-200 status rejection, the existing media boundary, and
the origin's `no-store` response directive. Inspector runs separate Go and Rust
policy adapters, retaining their source revisions, executable hashes, exact
case decisions and URLs. Both cores matched 15/15 cases locally. These adapters
perform no network request, so they cannot prove TLS identity, the connected
DNS destination, absence of an intermediary cache, unambiguous HTTP framing,
or controller/mutation authority. All REG-08 parent cases remain `NOT_RUN`;
conformance remains `NOT_ESTABLISHED`.

The [9 local TLS-origin subconditions](../vectors/0.10.0/reconciled-spec/reg08-tls-origin.json)
connect to short-lived loopback TLS servers under exact approved IP endpoints.
The servers use newly generated certificates for the web DID domain or another
domain. Inspector pins the Go and Rust source revisions, executable hashes,
independent decisions, and the Rust dependency resolution in
[`registry-tls-origin-Cargo.lock`](../verification/0.10.0/reconciled-spec/registry-tls-origin-Cargo.lock).
Both cores matched 9/9 decisions locally. This verifies a TLS handshake and
certificate-name/chain check, not an HTTP response on that same connection.
No authenticated record or controller/mutation history is established; all
REG-08 parent cases remain `NOT_RUN` and conformance `NOT_ESTABLISHED`.

The [13 local authenticated HTTP subconditions](../vectors/0.10.0/reconciled-spec/reg08-http-record.json)
exercise the Go and Rust Registry fetchers against isolated loopback TLS
servers. The server checks the exact GET, Host, and request cache directive;
the cores check the approved destination, certificate name, status, response
media and cache directive, one bounded `Content-Length`, JSON record, and key
proofs on the same TLS connection. Inspector pins the core source revisions,
executable hashes, proof fixture, vector, and Rust dependency lock. Both cores
matched 13/13 decisions locally. This bounded adapter rejects chunked and
other response framing, and does not establish controller writes, tombstones,
or mutation history. All REG-08 parent cases remain `NOT_RUN` and full
conformance remains `NOT_ESTABLISHED`.

The [18 creation and transition subconditions](../vectors/0.10.0/reconciled-spec/reg08-transition-shape.json)
invoke compiled Go and Rust predicates with independent, signed record pairs.
They check version increments, controller immutability, retained key material,
terminal deactivation, and the active signing endorser for a newly added KEM
key. Both cores matched 18/18 decisions locally. The pair inputs are supplied
by the test; neither predicate proves that a trusted source supplied a
complete history, authenticated a controller or operator, or committed a write
atomically. Inspector records those boundaries as `NOT_RUN`, as well as every
REG-08 parent case and full conformance.

The [15 history continuity subconditions](../vectors/0.10.0/reconciled-spec/reg08-history-continuity.json)
run the compiled Go and Rust predicates from a supplied version-1 creation
through a current, proof-valid record. They include missing and repeated
versions, time regression, invalid mutations, terminal deactivation, and a
current record that differs from the last supplied version. Both cores matched
15/15 decisions locally. This verifies the asserted sequence only: the input
is a local fixture, not an authenticated Registry mutation log. Inspector keeps
source history, controller authentication, atomic writes, all REG-08 parent
cases, and conformance unestablished.

The [11 write admission subconditions](../vectors/0.10.0/reconciled-spec/reg08-write-admission.json)
exercise the compiled cores with a local fixture authority. They check
controller creation, exact expected version, operation-scoped delegation,
invalid mutations, and denial when the fixture provides no actor. Both cores
matched 11/11 decisions locally. The fixture's actor and scope are test inputs,
not verified credentials or authenticated management state. Inspector reports
those deployment boundaries, atomic writes, source history, all REG-08 parent
cases, and complete conformance as unobserved.

The [8 expired-key recovery subconditions](../vectors/0.10.0/reconciled-spec/reg08-expired-key-recovery.json)
check the boundary between ordinary record validation and an authenticated
Registry mutation. A previously `active` record with an accepted but expired
signing key remains invalid for ordinary reads, while the local controller or
scoped operator may add a new, proven, usable signing key. Revoked prior keys,
invalid prior proofs, stale versions, and absent fixture credentials are
rejected. This observes only the bounded predicate against local fixture
authority; credential authentication, delegation provenance, authenticated
source history, atomic writes, REG-08 parent cases, and complete conformance
remain unobserved.

The [13 transaction boundary subconditions](../vectors/0.10.0/reconciled-spec/reg08-transaction-boundary.json)
run the two cores with a process-local store that supplies source identity,
current record, complete history, tombstone and fixture authority to one
transaction callback. They observe creation, mutation, version conflict,
history mismatch, scoped delegation, terminal name reservation and expired-key
recovery, including whether the fixture changed state on failure. The fixture
is not a durable store or credential verifier. Authenticated source history,
credential and delegation provenance, durable atomic writes, all REG-08 parent
cases and complete conformance remain unobserved.

The [12 local durable-write subconditions](../vectors/0.10.0/reconciled-spec/reg08-durable-write.json)
run each write in a separate Go or Rust process against an isolated single-DID
journal. They observe restart recovery, complete history and tombstones, stale
version and missing fixture-credential rejection, source binding on open,
fail-closed incomplete tails, and expired-key repair after restart. This is a
bounded local journal observation on the CI host. Deployed source and credential
authentication, delegation provenance, remote atomic writes, all REG-08 parent
cases and complete conformance remain unobserved.

The [8 local administrator mTLS subconditions](../vectors/0.10.0/reconciled-spec/reg08-admin-mtls.json)
run controller writes through fresh server-side TLS handshakes and the same
single-DID journal. A configured client CA verifies the certificate; an exact
leaf-certificate fingerprint maps it to the controller identifier. Separate
processes observe creation, denial of absent, unrecognized or untrusted certificates,
wrong-controller denial, source mismatch, activation and stale-version denial.
This is a bounded reference administrator binding, not a required wire API.
The deployed public source, production request framing, scoped delegation and
remote atomic writes remain unobserved. REG-08 parent cases and complete
conformance remain `NOT_RUN` or `NOT_ESTABLISHED`.

The [7 public-journal binding subconditions](../vectors/0.10.0/reconciled-spec/reg08-public-binding.json)
start with an authenticated local administrator write, then compare its journal
record with a newly fetched HTTPS record from the exact configured web origin.
The runtime checks matching and different records, a journal source mismatch,
unapproved origins and destinations, and wrong TLS names or roots in both
cores. This proves only one bounded publication snapshot. The actual deployed
public server's storage, production administrator framing, delegation state,
remote atomic writes and all REG-08 parent cases remain unobserved.

The [5 shared local journal publication subconditions](../vectors/0.10.0/reconciled-spec/reg08-public-journal.json)
commit a controller write through mTLS, close that writer, and start a public
HTTPS publisher that reads the same durable journal. Inspector checks the
actual response body and independently calls each core's HTTP reader. Creation
and activation publish versions 1 and 2 with new five-second response windows;
wrong source, wrong DID and missing journal fail before publication. This
demonstrates the local reference publisher's storage linkage, not the storage
or server behavior of a deployed service. All REG-08 parent cases remain
`NOT_RUN` and complete conformance remains `NOT_ESTABLISHED`.

The [6 local Registry service subconditions](../vectors/0.10.0/reconciled-spec/reg08-service-storage.json)
run a separate Go service executable with public HTTPS and administrator mTLS
listeners backed by one live journal. Inspector observes an empty source,
controller creation and activation, unchanged publication after stale and
malformed writes, and restart recovery. The Go and Rust core HTTP readers
then read the service's public endpoint. Every core read attempt and its
caller-sampled time is retained: a read crossing a whole-second boundary may
fail closed because the service issued a response after the caller sampled
`now`; only that `RECORD_INVALID` result triggers one fresh read with a new
clock sample. This records the availability limit rather than treating the
first refusal as a successful observation. The CI job pins the service and
both core revisions. This local run does not establish ownership of deployed
storage, authenticated operator delegation, remote atomic writes, any REG-08
parent case, or complete conformance.

Run the revision-bound checks against the exact spec checkout:

```sh
python3 -B scripts/test_reconciled_spec_catalog.py
python3 -B scripts/test_reconciled_spec_reg08_media.py
python3 -B scripts/reconciled_spec_catalog.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-spec-inventory.json
python3 -B scripts/reconciled_spec_reg08_media.py --spec-root /path/to/sage-spec \
  --report /tmp/reconciled-reg08-media.json
python3 -B scripts/test_observe_reconciled_reg08_media.py
python3 -B scripts/observe_reconciled_reg08_media.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-media.json
python3 -B scripts/test_observe_reconciled_reg08_envelope.py
python3 -B scripts/observe_reconciled_reg08_envelope.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-envelope.json
python3 -B scripts/test_observe_reconciled_reg08_record_shape.py
python3 -B scripts/observe_reconciled_reg08_record_shape.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-record-shape.json
python3 -B scripts/test_observe_reconciled_reg08_record_proofs.py
python3 -B scripts/observe_reconciled_reg08_record_proofs.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-proofs.json
python3 -B scripts/test_observe_reconciled_reg08_origin_policy.py
python3 -B scripts/observe_reconciled_reg08_origin_policy.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-origin-policy.json
python3 -B scripts/test_observe_reconciled_reg08_tls_origin.py
python3 -B scripts/observe_reconciled_reg08_tls_origin.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-tls-origin.json
python3 -B scripts/test_observe_reconciled_reg08_http_record.py
python3 -B scripts/observe_reconciled_reg08_http_record.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-http-record.json
python3 -B scripts/test_observe_reconciled_reg08_transition_shape.py
python3 -B scripts/observe_reconciled_reg08_transition_shape.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-transition-shape.json
python3 -B scripts/test_observe_reconciled_reg08_history_continuity.py
python3 -B scripts/observe_reconciled_reg08_history_continuity.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-history-continuity.json
python3 -B scripts/test_observe_reconciled_reg08_write_admission.py
python3 -B scripts/observe_reconciled_reg08_write_admission.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-write-admission.json
python3 -B scripts/test_observe_reconciled_reg08_expired_key_recovery.py
python3 -B scripts/observe_reconciled_reg08_expired_key_recovery.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-expired-key-recovery.json
python3 -B scripts/test_observe_reconciled_reg08_transaction_boundary.py
python3 -B scripts/observe_reconciled_reg08_transaction_boundary.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-transaction-boundary.json
python3 -B scripts/test_observe_reconciled_reg08_durable_write.py
python3 -B scripts/observe_reconciled_reg08_durable_write.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-durable-write.json
python3 -B scripts/test_observe_reconciled_reg08_admin_mtls.py
python3 -B scripts/observe_reconciled_reg08_admin_mtls.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-admin-mtls.json
python3 -B scripts/test_observe_reconciled_reg08_public_binding.py
python3 -B scripts/observe_reconciled_reg08_public_binding.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-public-binding.json
python3 -B scripts/test_observe_reconciled_reg08_public_journal.py
python3 -B scripts/observe_reconciled_reg08_public_journal.py \
  --spec-root /path/to/sage-spec --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-core-public-journal.json
python3 -B scripts/test_observe_reconciled_reg08_service_storage.py
python3 -B scripts/observe_reconciled_reg08_service_storage.py \
  --spec-root /path/to/sage-spec --service-root /path/to/sage-registry-service \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --report /tmp/reconciled-reg08-service-storage.json
```

Next, bind the deployed public server's actual storage to the administrator
write state, define production request framing and controller-authorized operator scopes,
then bind the local journal to deployed storage semantics and verify complete
mutation log, record and tombstones as one atomic transaction. Expand the
bounded HTTP adapter's accepted framing only with equally explicit ambiguity
checks. Run those paths against isolated local fixtures and retain actual
observations.
Only then can Inspector assess `REG-08-P` and `REG-08-N04` as complete cases.
The older 481-case and 489-case evidence directories remain historical.
