# External admitted-worker child issuance fixtures

These external Go/Rust programs use only public native MCP and Guard APIs.
They send a fixed inert root request over loopback. Its actual admitted worker
captures the exact inbound signed envelope and supplies its native parent
admission to protected downstream issuance. Separate B-owned policy, signing
key, capture, request identity and journal govern the child.

The fixture issues the child but never transmits or executes it. Its sender
always refuses; the child journal must contain only its initial open event.
The root returns one inert signed acknowledgement, not a child result.
Own policy denial, unavailable measurement and signing failure exercise only
ordinary local provider refusals. After shutdown the same parent admission
must refuse authorization. There is no general tool, shell command, arbitrary
file read, deployed registry or attack reproduction.

The independent artifact oracle and scenario units are
`scripts/inspect_hop_issuance.py` and `scripts/test_hop_issuance.py`.
Source revisions, adapter hashes and dependency locks are pinned. Fixture
registry states, public deterministic keys and in-memory loaded measurements
remain explicit local assumptions. Full downstream execution and deployment
conformance remain open.
