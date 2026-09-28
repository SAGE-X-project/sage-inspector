# Current-spec eip155 deployment and claim binding

REG-06 requires a pinned eip155 deployment before a resolver or claim flow
can assert conformance. The binding includes chain and registry identity,
deployed code hash and upgrade policy, authenticated ABI mapping to Registry
sections 1–5, operator and transaction authority, finalized-node readiness,
and measured costs and latency. The claim commitment is SHA-256 of the
domain prefix, zero byte, and JCS-encoded claim. A reveal must use the same
controller after the commit block and within 256 blocks; creation consumes
the commitment atomically, while activation is separate.

The [fixed scenarios](../vectors/0.10.0/reg06-scenarios.json) distinguish a
complete synthetic configuration from an unknown registry address, changed
code hash, missing ABI section, and record/key reads from different finalized
blocks. Each of the five cases has a runtime fixture and a separate
deployment-review fixture. The claim control pins six fields, 32 salt bytes,
the commitment hash, the first and last permitted reveal blocks, a late
block, and a different controller. The hash was also cross-checked with an
independent Node implementation. These are bounded unit controls, not an
on-chain registration test.

The [preserved Go/Rust run](evidence/current-spec/reg06/) pins `sage-spec`
`5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`b9e60759850a18cdea4545f0caf19b862f991845`. Reassess its 215 runtime
observations per core, fixture hashes, and subject identity with
`python3 -B scripts/check_current_spec_reg06_evidence.py`.

Both current primitive adapters return `UNSUPPORTED` for all five complete
eip155 binding operations. Every deployment-review track is `NOT_RUN` because
no pinned contract address, deployed bytecode observation, or authenticated
ABI evidence was supplied. The [pinned source review](evidence/current-spec/reg06/source-review.json)
finds that the older Go Agent Card client uses Keccak-256 over Ethereum ABI
parameters and a one-to-sixty-minute reveal window. It cannot be treated as
the current SHA-256/JCS, block-bounded claim. Rust's local Registry gate also
does not establish a deployed eip155 binding. Source review does not replace
a deployment review. Full REG-06 conformance remains `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 164 `UNSUPPORTED`, 33 `PARTIAL`, and
266 `NOT_RUN`; Rust has 12 `FAIL`, 163 `UNSUPPORTED`, 40 `PARTIAL`, and 266
`NOT_RUN`.
