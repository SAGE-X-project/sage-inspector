# Current-spec HTTP failure handling

MSG-06 separates unauthenticated failures from authenticated application
failures. Authentication, policy, and replay failures require the same generic
401 response; an unauthenticated response cannot authorize a retry, downgrade,
or result use. After peer authentication, an application failure requires a
signed response. TLS with server authentication remains required.

Four fixtures bind this rule to the current spec revision. The positive case
reuses the independently signed application-failure request/response from the
earlier HTTP boundary suite. Inspector independently verifies both Ed25519
signatures, the response's request hash and content digest, and the declared
failure result. It executes only RFC 9421 response-base construction and digest
validation in each core. A separate local vector fixes identical generic 401
bytes for authentication, policy, and replay causes. The three negative cases
describe a detailed 401 error, an unsigned application failure presented for
result consumption, and a signed response over unauthenticated transport.
Each requires zero protected result consumption, authorized retries, and
downgrades; those are expected effects, not observations.

The signed control uses the earlier cryptographic boundary's opaque plaintext
test payload. It does not establish a complete SAGE envelope exchange or a
successful end-to-end failure response. The generic 401 vector is independently
checked fixture data, not an observed core response. Neither core adapter
exposes a full `sage.http.verify` receiving and result-consumption operation,
so the three negative cases cannot yet show rejection or effect counts. No
network traffic or attack-capable reproduction is used.

The [preserved 52-case Go/Rust run](evidence/current-spec/msg06/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`8851a0fa86ae3bed4fbc3803d7a0c5fd7c052001`. Recheck fixtures, runner
hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_msg06_evidence.py`.

Rust matches the signed failure response base and digest, leaving MSG-06-P
`PARTIAL`. Go's base omits the signed `tag` parameter, making it `FAIL` at the
primitive layer. MSG-06-N01 through N03 are `UNSUPPORTED` in both cores; no
response routing, result-consumption, or protected-effect observation was
made. Across all 481 cases, Go has nine `FAIL`, 26 `UNSUPPORTED`, 17
`PARTIAL`, and 429 `NOT_RUN`; Rust has two `FAIL`, 26 `UNSUPPORTED`, 24
`PARTIAL`, and 429 `NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
