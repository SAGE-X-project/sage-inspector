# Current-spec request-bound HTTP responses

MSG-03 requires a response signature to cover the exact retained original
request components, including its `Signature` field, and to come from the
expected recipient. The five fixtures contain a signed 200 response and four
conditions: a changed stored request `Signature`, absent request context,
an independently signed response from another peer, and an unsigned success
response. The control request is the [MSG-02 signed control](current-spec-msg02-evidence.md),
so the fixture checker verifies both its request signature and this response
signature independently with OpenSSL. It also reconstructs the expected
response base and confirms that changing the retained request `Signature`
invalidates the response signature. The response signing private keys were
discarded after fixture generation.

The control bodies contain sender/version projections but are not complete
chapter 08 envelopes. `MSG-03-P` exercises only the RFC 9421 response base
and received-content digest primitives; it cannot establish complete SAGE
response acceptance or protected result consumption. Full SAGE cases provide
the expected response DID and fixed test time as trusted inputs.

The [preserved 36-case Go/Rust run](evidence/current-spec/msg03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go core
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust core
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`2ab14c10bff2cd07cfbc3f6a8e3573c2df45b055`. Recheck all fixture
relationships, runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_msg03_evidence.py`.

Both core adapters reject missing request context in `MSG-03-N02` and a
success response with no signature headers in `MSG-03-N04`; these are partial
primitive results. Rust matches the positive response base and digest,
yielding `PARTIAL`. Go omits the `tag` parameter from the response base, the
same defect observed for requests, so the positive case is `FAIL`.
`MSG-03-N01` and `N03` remain `UNSUPPORTED`: no current adapter exposes a
complete `sage.http.verify` operation that checks retained-request binding,
authorized response peer, and protected result consumption. The independent
vector checker proves the intended cryptographic relationships but does not
substitute for a core receiving-path observation.

Across all 481 current cases, Go has seven `FAIL`, twelve `UNSUPPORTED`,
seventeen `PARTIAL`, and 445 `NOT_RUN`. Rust has two `FAIL`, twelve
`UNSUPPORTED`, twenty-two `PARTIAL`, and 445 `NOT_RUN`. Neither subject has
a fully passed current case; overall conformance is `NOT_ESTABLISHED`.
