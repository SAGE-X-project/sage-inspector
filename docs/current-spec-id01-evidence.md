# Current-spec DID syntax

ID-01 defines the `did:sage` grammar, supported registry-kind parsing,
canonical spelling, length limits, and mandatory key fragment for DID URLs.
Six revision-bound fixtures cover a canonical web DID, a legacy kind alias,
percent encoding, mixed-case domain, an overlong DID, and a key URL missing
its fragment. They are tied to the independently audited registry vectors
and pinned DID syntax text. Every malformed-DID probe includes the same
valid web DID as a control, so rejecting every input cannot count as a match.

The [preserved 124-case Go/Rust run](evidence/current-spec/id01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`c53940c59541db6a0907654282946b279c3e4fee`. Recheck fixture
relations, runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_id01_evidence.py`.

Both current core DID validators reject the canonical web DID and accept
the forbidden `eth` kind alias. The percent-escape, mixed-case, and overlong
candidate inputs are rejected, but their valid controls are also rejected;
those pairs therefore remain `FAIL`, not successful negative tests. The
overlong input also exceeds the agent-segment bound, so this one probe does
not isolate the 256-byte total limit. Neither adapter exposes the DID-URL
fragment parser; the missing-fragment case is `UNSUPPORTED`. The positive
case exercises only DID acceptance, not the full key URL condition, and its
observed DID rejection is already a mismatch.

Five ID-01 cases are `FAIL` and one is `UNSUPPORTED` in each core. Across all
481 cases, Go has 16 `FAIL`, 75 `UNSUPPORTED`, 33 `PARTIAL`, and 357
`NOT_RUN`; Rust has ten `FAIL`, 74 `UNSUPPORTED`, 40 `PARTIAL`, and 357
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
