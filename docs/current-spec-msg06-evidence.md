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
