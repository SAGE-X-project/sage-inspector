# sage-inspector

Conformance and diagnostics tool for SAGE: runs the
[sage-spec](https://github.com/SAGE-X-project/sage-spec) test vectors
against the Go core and explains individual signed messages and agent
cards. It imports the Go core [`sage`](https://github.com/SAGE-X-project/sage)
as a library.

| Command | What it does |
|---|---|
| `sage-inspector vectors -dir <sage-spec>/vectors` | Runs every vector suite and reports pass/fail per vector (the Go core's own `sage-vectors check` stops at the first failure per run) |
| `sage-inspector request -f req.http [-key HEX]` | Parses a raw HTTP request, shows the signature label, keyid and DID, covered components, the reconstructed signature base, the Content-Digest check and timing; verifies with `-key` |
| `sage-inspector response -f resp.http -request req.http [-key HEX]` | Same for a response, including whether it is bound to the request with `;req` |
| `sage-inspector card -f agent-card.json` | Parses and validates an A2A agent card and verifies its proof over the JCS form without `proof` |

All commands accept `-json` for machine-readable output and exit 1 when a
check fails.

## Install

```bash
go install github.com/sage-x-project/sage-inspector/cmd/sage-inspector@latest
```

## Examples

```bash
git clone https://github.com/SAGE-X-project/sage-spec
sage-inspector vectors -dir sage-spec/vectors
# pass  crypto   ed25519-sign                 deterministic
# ...
# 26 passed, 0 failed (spec 1.0.0-draft.1)

# capture a request (for example with mitmproxy or tcpdump) into req.http
sage-inspector request -f req.http -key 0x<hex ed25519 public key> -ignore-age
```

Public keys are hex: 32 bytes for Ed25519, 33 or 65 bytes for secp256k1,
`p256:` plus 65 bytes for P-256.

## What is and is not checked

`request` and `response` run the Go core's strict verification with the
replay check disabled (a captured message is by definition old) and, with
`-ignore-age`, without the freshness window. They do not resolve DIDs on
chain; pass the key explicitly. `card` verifies the proof signature but does
not compare the card with the on-chain record.

## Roadmap

- Capture proxy that records signed exchanges for later inspection.
- HPKE init payload and response envelope inspection.
- On-chain key resolution (`-network sepolia`) for `request` and `card`.

## Licence

LGPL-3.0 (see `LICENSE`), the licence of the Go core it links.
