# Current-spec HPKE admission boundary

HPKE-06 limits each handshake payload to 16 KiB and requires closed schema
and fixed binary lengths to be checked before resolution or Diffie-Hellman.
A local rate/admission check may precede authentication, but it cannot claim
peer identity. Cookie metadata cannot change the authenticated transcript or
make an unsigned initiation valid. Authentication failures are generic and
must not disclose secrets in logs.

Five revision-bound fixtures cover selected boundaries. The positive fixture
is an otherwise valid completion padded with JSON whitespace to exactly
16,384 bytes. The next fixture adds one byte to the same completion. A third
uses an invalid ephemeral-key length. Two initiation admission fixtures
require rejection when cookie metadata accompanies an unsigned initiation
and require a generic failure with no secret-bearing log entry. The first
three are tied to the independent HPKE schedule vectors; the latter two use
the same valid initiation bytes and a fixed test-only private-key marker.

The independent HPKE audit verifies the source vectors and fixture relations,
not core behavior. Current Go and Rust primitive adapters do not expose
complete handshake admission, pre-cryptographic work ordering, a signed
envelope boundary, or effect and diagnostic-log instrumentation. Consequently
these fixtures cannot establish full HPKE-06 conformance through those
adapters. A future version-matched subject adapter must expose the receiving
boundary and bounded effects before a complete verdict can be assigned.

The [preserved 81-case Go/Rust run](evidence/current-spec/hpke06/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`a53ab6dd373816920ec7296e6086dfd3b5b218d4`. Recheck fixture
relations, runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_hpke06_evidence.py`.

All five HPKE-06 cases are `UNSUPPORTED` in both cores. Across all 481
cases, Go has 11 `FAIL`, 48 `UNSUPPORTED`, 22 `PARTIAL`, and 400 `NOT_RUN`;
Rust has five `FAIL`, 47 `UNSUPPORTED`, 29 `PARTIAL`, and 400 `NOT_RUN`.
Overall conformance is `NOT_ESTABLISHED`.
