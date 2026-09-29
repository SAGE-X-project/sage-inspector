# Current-spec HTTP receiving boundary

MSG-04 requires bounded HTTP framing and schema checks before public-key work,
and no protected dispatch before every verification succeeds. Six Inspector
fixtures use the independently signed MSG-02 request as a small control. The
five negative inputs isolate a duplicate `Content-Type`, simultaneous
`Transfer-Encoding: chunked` and `Content-Length` with a correctly encoded
chunked body, a compact recipe for `16 MiB + 1` received body bytes, exactly
`32 KiB + 1` HTTP field bytes, and an injected resolver timeout. The field
count sums each header line including its CRLF, excluding the request line and
terminating empty line. The vector checker verifies each byte relation and
limit. Negative fixtures require zero `protected_dispatches`; this is an
expected effect, not an observed one.

The [preserved 42-case Go/Rust run](evidence/current-spec/msg04/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go core
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust core
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`4843fe5718bb294303b1a91b1ad3e1566a290027`. Recheck fixture relations,
runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_msg04_evidence.py`.

The positive request tests only RFC 9421 base construction and received-body
digest. Rust matches both, yielding `PARTIAL`; Go omits the signed `tag`
parameter from the base, yielding `FAIL` from the same root issue observed
earlier. All five negative cases are `UNSUPPORTED` in both subjects because
neither current core adapter exposes a complete `sage.http.verify` receiving
entry point. In particular, the compact oversize recipe is not evidence that
the core expanded and rejected `16 MiB + 1` bytes: the current adapter reports
`UNSUPPORTED` before that operation. There is no observation of rejection
ordering, resolver fail-closed behavior, or protected effect counts. The
control body is not a complete chapter 08 envelope, so positive full-request
acceptance is also untested.

Across all 481 current cases, Go has eight `FAIL`, seventeen `UNSUPPORTED`,
seventeen `PARTIAL`, and 439 `NOT_RUN`. Rust has two `FAIL`, seventeen
`UNSUPPORTED`, twenty-three `PARTIAL`, and 439 `NOT_RUN`. Neither subject has
a fully passed current case; overall conformance is `NOT_ESTABLISHED`.
