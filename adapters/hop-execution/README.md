# Native protected hop consumers

These external programs import the exact Go and Rust core revisions recorded in
`docs/evidence/hop-execution.json`. They run three separate localhost processes:
A issues a root to B, B issues and transmits a child from the actual admitted
Invocation, and a separate A receiver executes a fixed inert read and returns a
signed result. B consumes that result and returns the child outcome to the root
Client. The programs do not read user-selected files or execute arbitrary tools.

All keys, Registry records, policy, component bytes and clocks are public local
fixtures. The receiver obtains the exact admitted parent from a protected shared
fixture file; this is not autonomous deployed context acquisition. Replay stores
are populated through real signed native bootstrap handshakes after advancing
both logical clock dimensions through quarantine, then closed and reopened using
public APIs. No replay rows, READY state or parent authority are fabricated.

Run `scripts/inspect_hop_execution.py` for the independent artifact oracle, source
checks and bounded process driver. Its scope does not establish a selected host,
ADK loader, authoritative blockchain Source, full HPKE handshake oracle or full
protocol conformance. Artifact refusal tests do not send altered network traffic.
