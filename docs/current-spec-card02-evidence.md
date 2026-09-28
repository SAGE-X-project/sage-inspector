# Current-spec Agent Card proof

CARD-02 requires the exact SAGE proof type, a full registry key URL, an
exact algorithm, canonical signature bytes, and the `sage-card-0.10.0` NUL
domain over JCS with only `proof.proofValue` removed. Five revision-bound
fixtures cover a valid card, a forbidden legacy W3C suite label, a changed
verification method, a signature made under `sage-card-0.9.0`, and an
invalid base64url signature value. The valid, legacy, and changed-method
cards come from independently audited registry vectors. The wrong-domain
fixture keeps the unsigned card identical; OpenSSL confirms its signature
works under the wrong domain and fails under the required domain.

The [preserved 149-case Go/Rust run](evidence/current-spec/card02/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`aeb0d5fae4cc41d84b73e09dd93d70c7d08f490b`. Recheck the fixture,
signature, runner, and assessment identities with
`python3 -B scripts/check_current_spec_card02_evidence.py`.

Neither primitive adapter exposes `sage.card.verify`; all five CARD-02
cases remain `UNSUPPORTED`. A separate bounded
[signature-primitive run](evidence/current-spec/card02/primitives/report.json)
shows that both cores accept the valid, legacy-type, and altered-method
signatures as generic Ed25519 signatures and reject the wrong-domain
signature when given the correct domain bytes. This demonstrates why
generic signature verification cannot enforce proof type or registry key
selection. The malformed base64url value is checked at fixture level;
no core card parser consumed it. These observations do not establish
full CARD-02 conformance.

Across all 481 cases, Go has 18 `FAIL`, 98 `UNSUPPORTED`, 33 `PARTIAL`, and
332 `NOT_RUN`; Rust has 12 `FAIL`, 97 `UNSUPPORTED`, 40 `PARTIAL`, and 332
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
