# MCP Client provenance: core boundary evidence

Recorded 2026-09-24 for SAGE 0.10.0. This addendum pins later Go and Rust
core revisions separately from the frozen 2026-09-24 INS-11 evidence. It does
not replace the [Agent host deployment audit](agent-host-deployment-audit.md)
or change its eight `NOT_RUN` scenarios and 40 unobserved steps.

The [archived report](evidence/mcp-client-provenance/report.json) identifies
the exact source files and SHA-256 values for Go
`62242937995d152e3c2a6d4bbb8a08229680684a` and Rust
`e5d6b43b064e02ae467b4dd835272c3fc4ea29d1`. The six allowlisted
tests separately cover trusted original-input capture at the MCP root,
parent authorization at an MCP hop, and admission limited to an active
worker. The Go root and hop tests include a successful exchange; the Rust
root test reaches journal opening and its hop test includes a successful
localhost TCP exchange. The raw stdout and stderr for each invocation are
archived with hashes.

Reproduce from the two pinned source checkouts:

```sh
python3 -B scripts/inspect_mcp_client_provenance.py \
  --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core \
  --output /tmp/mcp-client-provenance-recheck
python3 -B scripts/check_mcp_client_provenance.py \
  --evidence /tmp/mcp-client-provenance-recheck \
  --go-root /path/to/sage \
  --rust-root /path/to/rs-sage-core
```

The runner executes fixed test names with offline dependencies and a temporary
build directory. The checker rejects altered source inventory, case set,
commands, log hashes, missing individual test success, and any attempt to
promote the result to host or protocol conformance. CI checks the archived
evidence and checker regressions without treating CI's Inspector checkout as
a fresh execution of the two cores.

**Verdict:** `CORE_BOUNDARY_OBSERVED`; deployed host `NOT_RUN`; conformance
`NOT_ESTABLISHED`. No deployed Agent host executable, configuration, or
external witness is bound. Core-local tests cannot establish that a real
host captures the user's exact input before plugin or MCP processing, always
uses the root versus hop path correctly, or routes every protected effect
through the required boundary. Those observations remain in the existing
host audit and require a fixed host and independent observation.
