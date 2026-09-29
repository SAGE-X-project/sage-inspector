# Current-spec HTTP component binding

MSG-02 fixes the ordered request components and binds the sender DID, protocol
version, body digest, target, and authority. The six fixtures contain a
signed HTTP control and five isolated conditions: changed target, a validly
signed attacker endpoint with untrusted forwarding headers, body whitespace
added without updating the digest, a missing covered version header, and an
unknown header/body version re-signed with the same key. The fixture checker
reconstructs the expected base, recomputes digests, verifies the control and
the two re-signed variants with OpenSSL, and checks each mutation. The signing
private key was discarded after fixture generation.

The control body includes matching `did` and `version` projections but is not
a complete chapter 08 envelope. `MSG-02-P` therefore tests only the ordered
RFC 9421 base and received-content digest; it cannot establish SAGE request
acceptance or protected effects. The full SAGE verification cases include a
trusted receiver endpoint and fixed test time in their inputs.

The [preserved 31-case Go/Rust run](evidence/current-spec/msg02/) uses
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go core
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust core
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`84303420690459ccb696ab9aab30b1ffcfe83906`. Reassess the fixture,
runner hashes, observations, and statuses with
`python3 -B scripts/check_current_spec_msg02_evidence.py`.

Both cores reject the stale digest in `MSG-02-N03` and the missing covered
version header in `MSG-02-N04`; these are `PARTIAL` results. Go's positive
base differs because it omits the `tag` parameter, the same root issue
observed under MSG-01, so `MSG-02-P` is `FAIL`. Rust matches the base and
digest, yielding `PARTIAL`. `MSG-02-N01`, `N02`, and `N05` are
`UNSUPPORTED`: the current core adapters do not expose a complete
`sage.http.verify` operation with trusted receiving endpoint, version policy,
and effect observation. A primitive rejection cannot establish that routing
or forwarding spoofing is rejected before dispatch.

Across all 481 current cases, Go has six `FAIL`, ten `UNSUPPORTED`, fifteen
`PARTIAL`, and 450 `NOT_RUN`. Rust has two `FAIL`, ten `UNSUPPORTED`, nineteen
`PARTIAL`, and 450 `NOT_RUN`. Neither subject has a fully passed current case;
overall conformance is `NOT_ESTABLISHED`.
