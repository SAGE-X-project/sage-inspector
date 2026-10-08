# Admitted-worker child issuance observation

This bounded observation pins Go
`1aaee98258e72aeeaba5a8c49fc9908b41ff29cd`, Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb` and normative source
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. The machine report is
[hop-issuance.json](hop-issuance.json); its independent signature and journal
oracle is [inspect_hop_issuance.py](../../scripts/inspect_hop_issuance.py).

`HOP_ISSUANCE_BOUND` records protected child issuance inside an actually running
native MCP worker. Go-to-Go, Rust-to-Rust, Go-to-Rust and Rust-to-Go root
exchanges each reach the worker and issue one child. Three ordinary own-provider
refusals in both cross-core directions cover policy, component measurement and
signing failure. Root completion is one inert acknowledgement; it does not
mean a child was sent or executed.

Inspector independently verifies the parent and root result Ed25519 proofs,
exact received envelope, framed capture of that envelope, distinct child
request/call/nonce, exact causal parent call, B's own policy/manifest, B's
role-bound signing key and canonical child proof. Native approval is one-use;
its durable issuance fence precedes signing. Allowed child journals contain
one open event and no transport/result events. Failed signing retains the
fence without creating a Client. Policy or measurement refusal creates neither
fence nor Client and attempts no signing. The retained actual parent admission
refuses after its worker and host finish.

Both external programs compile against the public cores. Exact clean source
revisions, selected source hashes, adapter bytes and existing dependency locks
are checked before execution and again before accepting the report. Unit tests
mutate only saved artifacts; they do not send malicious requests. Runtime
fixtures send only the fixed benign root request and exercise ordinary local
provider refusals. A saved report is not a signed attestation.

The child recipient is A in this fixture, making the intended chain A-to-B-to-A.
Only A-to-B is transmitted. Registry validation/finality, clocks, key custody
and loaded-instance appraisal are local fixtures. No Agent deployment, ADK
loader, blockchain Source, independent outer handshake oracle, downstream
transport/effect or complete normative case is established. Independent full
hop execution remains `NOT_RUN`; full conformance remains `NOT_ESTABLISHED`.
Earlier evidence and its exact revisions are retained without status changes.

Recheck the saved artifact and refusal scenarios:

```sh
python3 -B scripts/inspect_hop_issuance.py
python3 -B scripts/test_hop_issuance.py
```

For fresh execution use clean cores at the pins above, public dependencies
already cached and the pinned Rust core lock from
`verification/0.10.0/intent-issuance/Cargo.lock`:

```sh
python3 -B scripts/inspect_hop_issuance.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/hop-issuance.json
```

The [workflow](../../.github/workflows/hop-issuance.yml) repeats the saved
artifact checks, scenario units and ten fresh bounded observations. Continue
with independently observed downstream transport/execution and actual selected
Registry/host providers in the approved program order. This observation neither
selects the existing Sepolia candidate nor closes its 21 Registry obligations.
