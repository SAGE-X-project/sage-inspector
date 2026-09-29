# Current-spec send allocation and retransmission

SESSION-04 requires distinct atomic sequence allocation for concurrent sends.
Allocation survives transport failure; retransmission may use only the exact
stored ciphertext. The protocol forbids a new plaintext under an old key/nonce
pair and does not admit a separate MAC over unrelated caller-selected bytes.

Four revision-bound fixtures cover concurrent allocation, attempted reuse of
an allocated sequence after transport failure, the legacy separate-MAC path,
and plaintext replacement during retransmission. The fixtures are checked
against the independent 16-send concurrency and transport-gap scenarios and
the pinned normative SESSION-04 text. The Node audit validates those scenario
expectations independently; it does not execute a core implementation.

The [preserved 107-case Go/Rust run](evidence/current-spec/session04/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`7bce1fd7a771f13bb56360e8716cd072efd4b141`. Recheck the fixture
relations, runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_session04_evidence.py`.

Both current primitive adapters return `UNSUPPORTED` for all four stateful
operations. Their single-record seal/open calls cannot observe a concurrent
allocator, a failed transport, stored retransmission ciphertext, or the
absence of a separate MAC path across the full transport. The prior
SESSION-03 AEAD observations therefore cannot promote these cases. A future
stateful transport binding needs to expose the allocation point, emitted
ciphertext identity, and effect counters before a SESSION-04 verdict can be
established.

Across all 481 cases, Go has 11 `FAIL`, 63 `UNSUPPORTED`, 33 `PARTIAL`, and
374 `NOT_RUN`; Rust has five `FAIL`, 62 `UNSUPPORTED`, 40 `PARTIAL`, and
374 `NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
