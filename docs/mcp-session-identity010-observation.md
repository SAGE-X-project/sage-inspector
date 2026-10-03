# MCP session identity at record receipt

The [eleven-case suite](../vectors/0.10.0/mcp-session-identity010.json)
checks `sage-spec` revision `fa006fd917ad365eb554a27f4178301cd66e2379`,
especially SESSION-01 and TRANSPORT-01/02/03, at the bounded non-HTTP MCP
session receiver. It extends the earlier MCP transport report with negative
identity checks on both request and response records.

For each negative case, the outer DID, signing key URL, recipient or role is
changed and re-signed with the expected public fixture key. The other-signer
case retains the original identity declaration but signs with the opposite
registered public fixture key. An independent Node Ed25519 implementation
verifies every normal and changed outer signature before a Go or Rust receiver
sees it.
The companion unit test checks the semantic disagreement and signing role.

Local execution passed **44/44 cases** across Go/Go, Go/Rust, Rust/Go and
Rust/Rust at Go `fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`. The receiver rejected each
changed request without a record reservation or exposed RPC bytes; the original
request then opened exactly once. A changed response did not consume the
initiator's reply permit or create a reservation; the original response then
opened exactly once with its RPC bytes intact. The report pins spec and core
revisions, hashes the suite, runner, helper files, executable and observed
wire, and retains bounded process transcripts. CI builds both adapters from
the pinned cores and preserves the report and raw transcript.

```sh
python3 scripts/test_mcp_session_identity010_unit.py
python3 scripts/test_mcp_session_identity010.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --spec-root /path/to/sage-spec \
  --go-adapter /path/to/go-completion-adapter \
  --rust-adapter /path/to/rust-completion-adapter \
  --output /new/output/mcp-session-identity
```

Only fixed public test keys, controlled local Registry, replay and clock
dependencies, and an inert MCP RPC fixture are used. This checks the outer
transport identity at record receipt, not inner Guard authorization, native
MCP setup negotiation, deployed host enforcement, arbitrary recovery points
or full 0.10.0 conformance. The parent result remains `NOT_ESTABLISHED`.
