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
