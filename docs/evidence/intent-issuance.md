# Protected intent issuance and cross-core recovery

The dedicated issuer is public at Go
`d9d61d5d8daa9b2894ba6eddea2a771ccfe7ab54` and Rust
`eb0529922f2dd632357ceb1ed89eefb17cda9a29`. It binds captured original input,
locally selected peers, exact tool arguments, policy epoch and measured
components before using the active role-bound Ed25519 key. An opaque one-use
decision and a durable exclusive issuance fence precede key use. Successful
issuance returns a journaled Client; it does not send or execute the request.
The fence survives failure and restart, so uncertain issuance is not retried
by signing again at the same journal identity.

The [machine report](intent-issuance.json) records four bounded native process
observations. Inspector compiles the pinned core test binaries and starts only
their fixed issuance helpers. It uses an independent Python cryptography oracle
to verify the exact canonical envelope, Ed25519 proof, original-input framing,
policy and manifest digests, peer/key binding, expiry, fresh UUID and nonce,
issuance fence and append-only journal. The helper signing keys and input are
public test fixtures. These are native core test processes, not independent
external API consumers or deployed Agent hosts.

| Observation | Result |
| --- | --- |
| Go issues; fresh Rust process reopens the same signed journal | Verified; original envelope preserved and a second fixed handoff appended without signing |
| Go signing fails; fresh Rust process attempts the same journal identity | Verified; issuance fence preserved, no journal and no replacement signature |
| Rust issues; fresh Go process reopens the same signed journal | Verified; original envelope preserved and a second fixed handoff appended without signing |
| Rust signing fails; fresh Go process attempts the same journal identity | Verified; issuance fence preserved, no journal and no replacement signature |

The status is `ROOT_ISSUANCE_INTEROP`. The native Go/Rust suites additionally
cover policy rejection and changes, measurement failure, key-role and weak-key
rejection, stale decisions, one-use ownership, signing failures, admitted or
retired hop parents and quoted JSON argument preservation. Those core tests
remain separate from the four independent root observations. Independent hop
execution is `NOT_RUN`; the thirteen deployed-host controls remain `NOT_RUN`;
full conformance remains `NOT_ESTABLISHED`.

The protected host must supply key custody, policy, authoritative identity,
immutable component binding, protected storage and rollback control. The
current APIs do not prove these deployment obligations. Coordinated public
MCP owner/setup/admission assembly remains the next core task, followed by
external consumer binding and a pinned host inspection. This report supersedes
the older missing-issuer finding only at the new revisions; it does not alter
historical [public API audit](host-public-api.md) source hashes or verdicts.
The normative source remains `sage-spec`
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`.
No 0.10.0 wire rule or normative specification was changed.

## Reproduction

Use clean core checkouts at the two revisions above and fetch their public
dependencies first. Use Go 1.26.8, Rust 1.88.0 and Python with
`cryptography==50.0.0`. The Rust library intentionally ignores `Cargo.lock`;
Inspector stores the exact tested [dependency lock](../../verification/0.10.0/intent-issuance/Cargo.lock)
and includes its hash in the observed inputs. Copy it into the Rust checkout
before `cargo fetch --locked`; native compilation uses `--locked --offline`:

```sh
cp verification/0.10.0/intent-issuance/Cargo.lock /path/to/rs-sage-core/Cargo.lock
RUSTUP_TOOLCHAIN=1.88.0 python3 -B scripts/inspect_intent_issuance.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/intent-issuance.json
python3 -B scripts/inspect_intent_issuance.py --report /tmp/intent-issuance.json
python3 -B scripts/test_intent_issuance.py
```

Each run generates fresh call IDs and nonces, so report bytes differ. Inspector
checks the exact source hashes and bindings and verifies every new signature;
it does not compare random output with the saved report. Without core paths,
the script validates saved artifacts only and performs no native execution.
The dedicated CI job repeats native execution at the exact revisions and
preserves its fresh report as an artifact. Nine unit tests reject corrupted
or promoted evidence, including a valid fixture signature bound to the wrong
original input; they do not reproduce an attack against a host.
