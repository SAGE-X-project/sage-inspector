# Current-spec multi-hop observations

The [three signed fixtures](../vectors/0.10.0/exec-hop.json) exercise the
public `OpenHopClient` and `open_hop` boundaries in the pinned Go and Rust
cores. Their A-to-B envelope has a valid Ed25519 signature. B's new B-to-C
envelope has distinct request and call IDs, names the parent call, commits to
the exact upstream envelope bytes, and carries B's separately approved policy.
The independent checker validates both signatures and these links.

Both cores open and send exactly once when the parent and B-side policy allow
the operation. B-side policy denial and missing parent admission each prevent
journal creation and handoff. The [revision-bound observations](evidence/current-spec/exec-hop/)
are archived with the runner, bridge, source adapters, executable hashes, and
separate assessments. Reassess with
`python3 -B scripts/check_current_spec_hop_evidence.py`.

All three cases remain `PARTIAL`: these local tests do not prove that a deployed
host routes every downstream protected effect through the hop API, preserves
and rechecks parent admission across restarts, or obtains the denied parent
state from a real upstream `UNKNOWN` result. No original-user delegation is
inferred from the upstream digest.
