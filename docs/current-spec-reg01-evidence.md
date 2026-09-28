# Current-spec registry record boundaries

REG-01 requires a closed record with bounded, sorted keys and services;
names and key material cannot be reused, service names cannot collide with key
names, and the record retains at most 128 lifetime key entries including
revoked tombstones. A KEM entry uses the exact lowercase `x25519` algorithm
name, which denotes only its HPKE role.

Five [fixed public records](../vectors/0.10.0/reg01-scenarios.json) cover a
valid control, duplicate key name with distinct key material, duplicate
service name with distinct HTTPS endpoints, service/key fragment collision,
and a 129th revoked key. Supplemental controls cover a valid 128-entry record
and case-folded or unknown KEM algorithm names. Every entry has a valid
independently checked proof, including the invalid-record variants; the
algorithm variants re-sign their changed algorithm value. This isolates
record-shape failure from proof failure. The earlier Registry vector suite
also passes its independent 94-case, 17-scenario audit.

The [preserved 190-case Go/Rust run](evidence/current-spec/reg01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`42ddbf5f5e98c55830b546ae5c68ea7acc6d759e`. Reassess fixture, runner,
binary, and observation hashes with
`python3 -B scripts/check_current_spec_reg01_evidence.py`.

Neither current core primitive adapter exposes `sage.registry.record.verify`;
all five bound cases are `UNSUPPORTED`. A separate
[bounded signature run](evidence/current-spec/reg01/primitives/report.json)
shows both cores accept five isolated Ed25519 endorsement signatures. That
does not validate the enclosing record, its key roles, or its lifetime limit.
Full REG-01 conformance remains `NOT_ESTABLISHED`.

The old Inspector snapshot predates the current KEM `alg` clarification.
The unit checker uses its unchanged common record rules and pins the current
`sage-spec` chapter 09 and chapter 11 hashes through the current-spec
manifest. The source-hash check does not promote the historical snapshot to
the present normative text.

Across all 481 cases, Go has 18 `FAIL`, 139 `UNSUPPORTED`, 33 `PARTIAL`, and
291 `NOT_RUN`; Rust has 12 `FAIL`, 138 `UNSUPPORTED`, 40 `PARTIAL`, and 291
`NOT_RUN`.
