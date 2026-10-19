# Paired core handshake key authority inspection

This observer re-executes fixed memory units from public Go and Rust sources
against the adopted SAGE0.10.0 inventory. Run the dedicated CI workflow or,
inside its prepared Linux environment, `scripts/check_core_key_authority_evidence.py
--run --directory PATH --rust-root CHECKOUT`. A saved artifact can be checked
without compiling or contacting a service by omitting `--run` and `--rust-root`.
The execution entry point has no network destination, credential, arbitrary
message or negative-case selector. Contradictory messages remain authored units.

Both languages must complete every one of15 logical scenarios, including two
positive handshakes with an inert authenticated HTTP request and response,
before either mapped inventory row becomes PARTIAL. Go has15 leaves plus a
parent,16 named PASS; Rust has3 named tests with15 loop cases. The two mapped
rows are `didp-04-peer-document-ignored` and `didp-04-received-alias`.
A fresh report contains2PARTIAL581NOT_RUN. Missing evidence never promotes a
row. This is a separate subject, without unioning historical reports.

The cases cover normal and matched new KEM material; four unknown members at
each of the outer/initiation levels; local KEM mismatch; selected initiator or
responder signing-key revocation; Source error; and configured signing-key/local
material mismatch. Alternate signing-2 remains accepted from the first read.
Static Bob version3 retains original kem-1 bytes revoked and introduces kem-2
accepted, the ASCII-first usable key. This is not a Registry rotation transaction.
Both cores lack a peer DID-document input API. Rejection of extra closed-wire
members is not a generic DID-document parser or alias-linkage implementation.

The parser reconstructs attributed raw test output, verifies public Ed25519
signatures and closed typed message schemas, checks exact Source order and
key material/history, and independently derives public transcript hash/session
ID and request/response correlations. Source Ready/Validated/Finalized are
prevalidated fixture inputs. There is no controller observation or operating
Registry/finality proof. The Source digest commits the fixture key list,
not an entire authoritative record. Go keeps six positive handshake reads and
server retained replay entries3→5. Rust keeps six handshake/sixteen total reads
and four publications: server handshake3, client handshake2, server record5,
client record4. Phase counters are neither message totals nor durability proof.

Actual core Open/Seal assertions establish the inert plaintext exchange and
request replay/terminal response reuse refusal. Python checks public signatures,
framing and correlations; it does not independently decrypt AEAD or verify the
secret-dependent ACK. Captured application bodies are not full HTTP header bytes.
The authored calibration file contains public frames from owned core CI runs for
synthetic parser tests only. It is never substituted for a new native run.

Go acquisition pins the public module Version/Sum/GoModSum and critical DID
module metadata, independently derives whole-module/go.mod h1 from all796 public ZIP entry
hashes, verifies the cache and a complete temporary module copy,
uses a readonly graph without replacements, and records selected package inputs.
The actual race test uses Go1.26.8, separately from the original core's1.26.9
CI. A `.test` BuildInfo proves compiler/race settings, not compiled dependency
closure. Missing empty BuildSetting Value is normalized only as the Go format
specifies; mandatory values stay strict. Rust uses exact Git revision/tree,
all272 tracked Git-blob file hashes, Rust1.88.0 and the retained acquired Cargo.lock with offline/locked compilation.
That Inspector-owned lock input is not a committed core Git blob. Both native
test executable hashes, raw commands/output and before/after complete source
identity checks are retained. Selected source hashes and ordinary CI provenance
are not compiler-input closure, hardware attestation or a signed executable chain.
A separately obtained trustworthy CI run/source/artifact association is required;
a self-consistent JSON report alone cannot authenticate how it was generated.

The workflow separately records synthetic parser/provenance controls and
statement coverage for all three new observer/checker modules. Controls include
joint raw/hash edits, validly re-signed semantic drift, key/digest history changes,
wrong source/version/role, output misattribution/truncation or output outside RUN/PASS, noncanonical inner
completion JSON, replay phase mixing,
module/compiler/lock/source substitution and report edits. They are memory/temp
unit tests, not hostile service traffic. Successful parser controls do not count
as additional native cases or operating protection.

Old DIDP04 UNSUPPORTED, production-ingress UNSUPPORTED, card/HTTP/ingress partial
subjects and historical findings remain unchanged. Actual Registry/contract
Source, protected external custody, deployed listeners/host enforcement and full
DID/A2A/protocol conformance require their own evidence. SAGE0.10.0 and adopted
spec06b50e1 remain unchanged by this observer.
