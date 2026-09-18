# Durable replay denial and restart quarantine

The real Go and Rust cores now provide a compatible bounded local denial
journal. It is a trusted storage dependency, not a verifier: callers must only
reserve authenticated messages. No peer-provided verified flag, clock or path
can replace trusted endpoint processing.

## Contract

- Explicit new creation and empty reopen impose 360 seconds of both trusted UTC
  and monotonic elapsed time. Clock advance in only one domain cannot bypass it.
- Complete nonempty recovery is immediate if UTC has not moved behind persisted
  history. Missing files, torn rows, noncanonical or backward history fail closed.
- ID and nonce are reserved together in sender/recipient scope and denied through
  expires+30, inclusive. Initiation contexts remain denied per sender even across
  recipient changes and after nonce retention ends.
- Denial bytes are appended and synced before success. The parent directory is
  synced at creation. Exclusive lock files require explicit clean close; after
  unclean exit only deliberate operator recovery can remove the lock.
- Before final record acceptance, durable denial is staged before the endpoint
  gate. Gate failure releases no plaintext or sequence state, but denial remains
  and a repeated message fails even after reopen. The contract distinguishes durable denial from acceptance; failure does not
  promise deletion of staged denial. Existing synthetic stores may reject
  without retaining an entry; they must never publish a failed acceptance.
- Sessions are discarded on restart. The journal stores no keys, positive grants,
  restored sequence counters or execution status. It is separate from the Guard's
  durable business-execution ledger and does not establish exactly-once effects.

The implementation supports trusted Linux/macOS storage, 4096 rows and 1 MiB.
Other platforms fail initialization. Capacity exhaustion fails closed. There is
no compaction, automatic lost-state reset, stale-lock guessing or malicious disk
rollback protection. Filesystem sync semantics, path integrity and the trusted
clock remain deployment responsibilities; power-cut durability is not certified.

## Actual tests

Both cores consume the same 12-case / 53-operation fixture. It covers quarantine
boundaries, one-clock jumps, intact/empty/missing recovery, independent ID/nonce
and context scopes, exact retention boundaries, failed final gates, UTC/monotonic
rollback and expiry input bounds. Additional native tests cover writer exclusion,
partial and blank rows, capacity/storage failures and real authenticated
completion plus encrypted first-record/replay processing. Go additionally runs
a simultaneous duplicate-reservation test under the race detector; Rust uses
exclusive mutable ownership and a checked shared handle.

Inspector runs 24 real journal-process scenarios plus 20 cross-process recovery
scenarios across Go/Go, Go/Rust, Rust/Go and Rust/Rust. The latter cover clean
restart, the test child's own unclean exit, failed-gate persistence, lost state
with explicit replacement/quarantine and incomplete appended state. Synthetic
files stay inside newly created temporary directories. Lock removal occurs only
after the owned child has exited and after reopening with its lock was rejected.
No external process is killed and no network or attack-capable reproduction is
used. Interrupted-file simulation is local to these synthetic test journals.

This is actual filesystem/API/process evidence with injected trusted time. It
is not merely scripted PASS output, a physical power-loss experiment, a 360-second
wall-clock wait or a production replay/host conformance claim. Cryptographic
integration is tested in the native core tests; standalone journal controls do
not authenticate arbitrary supplied entries.

## Evidence

CI builds the reviewed merged core revisions:

| Core | Revision |
| --- | --- |
| Go | `972110ba9b1f0a56ae83c64478d0b73ce87cda3c` |
| Rust | `2f7a3e1ebc96212ae45120df7b855ecf494decbb` |

The runner records pinned core revisions, executable and fixture hashes, all
control inputs/results, callback counts, before/after synthetic journal snapshots with hashes and the raw
log hash. Expected outcomes stay in the Inspector runner and are not sent to the
adapters. CI adds a thirteenth report group, replay-journal010. Historical findings
remain unchanged and full conformance stays NOT_ESTABLISHED.

The next work is the deployed registry Source and chain-finality observation
contract, followed by unavoidable host enforcement and production storage/transport
integration. Durable execution-ledger recovery remains a separate Guard obligation.
