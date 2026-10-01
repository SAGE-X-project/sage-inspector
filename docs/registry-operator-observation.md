# Registry operator transaction observation

The [0.10.0 operator subcondition vector](../vectors/0.10.0/registry-operator/subconditions.json)
is copied byte-for-byte from `sage-spec` revision
`fa006fd917ad365eb554a27f4178301cd66e2379`. The
[local report](evidence/registry-operator-0.10.0/local-service-observation.json)
pins the merged Registry service revision
`baf5570578ddc19685ebe2a5bda4a284f45c8e05` and Go core revision
`9c7dce33202377721259d246acd7d973d2dc0d86`. Rust core's separate
expired-key regression test passed at revision
`ffa1234720f7a519b753471cfe315605be7deb1c`; this service observer does
not execute the Rust core.

Inspector generated short-lived local TLS certificates and exercised the
service's public and mTLS administrator endpoints. It observed 15 of the 17
subconditions with a bounded `PASS`, including exact scoped grants, stale and
competing commands, 128 active grants, public version changes, restart replay,
deactivation, and rejection of an incomplete local journal on restart. Each
result is a local observation at the pinned revisions, not a complete REG-03
or REG-08 parent-case verdict.

`expired-key-management` is `PARTIAL`: an active record's signing key expired,
the controller's grant revocation committed, and the grant history remained
readable. The observer did not run a protected-message authorization decision
against that expired key. `storage-authority-loss` is `NOT_RUN` because no
deployed origin, storage owner, clock source, or independent read/write observer
was supplied. The report retains `deployed_reg08: NOT_RUN` and
`conformance: NOT_ESTABLISHED`. Historical Registry evidence and its pinned
revisions remain unchanged.

Run the vector and report validation with:

```sh
python3 -B scripts/test_observe_registry_operator_service.py
```

Run the bounded local TLS observation with clean checkouts at the revisions
above:

```sh
python3 -B scripts/observe_registry_operator_service.py \
  --service-root /absolute/path/to/sage-registry-service \
  --go-root /absolute/path/to/sage \
  --spec-root /absolute/path/to/sage-spec \
  --output /absolute/path/to/local-service-observation.json
```

The observer checks all three source revisions before running. It copies the
independent vector, validates the report's case order and refuses to promote
missing deployment evidence into a conformance result. A later Inspector
adapter should execute a protected-message decision for the expired-key case;
deployed REG-08 still requires separate authority and storage evidence.
The `registry-operator-service` CI job repeats the local TLS observation at
those exact revisions and retains its generated report as a build artifact.
