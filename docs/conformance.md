# Fixture, observation and report contract

Schema version1, target protocol0.10.0, inspection profile `primitive-foundation`.
This contract belongs to Inspector tooling. It does not add a SAGE network profile.

## Independent expectations

Published input/output bytes from RFC5869 Appendix A.1–A.3 and the RFC6234 SHA-256
abc example are transcribed into `vectors/0.10.0/foundation.json`. RFC4648 examples
are explicitly adapted to SAGE's raw URL alphabet. Invalid encoding/JSON verdicts
are manually derived from cited spec rules. Neither the fixture assembly nor the
runner invokes SAGE to produce expected answers. No private keys are in the suite.

Independence means separate provenance for the **expected answer**, not independent
expert certification of this new runner. In particular, the example process adapter
uses the same reference code and only tests IPC plumbing. A future subject adapter
must call its own implementation, without reading the fixture's expected fields.
Report attribution is not authenticated publication: review and pin a trusted suite
hash before using third-party fixtures. The runner does not fetch source URIs.

## Suite schema

All declared fields are required and unknown/case-aliased fields are rejected.

- Root: `schema_version`=1, `protocol_version`=`0.10.0`,
  `profile`=`primitive-foundation`, `id`, `sources`, `cases`.
- Source: `id`, `kind` (`published` or `spec-derived`), `uri`, `reference`.
- Case: `id`, `operation`, `rule_ids`, `source_ids`, `derivation`, `input`, `expected`.
- Expected: `verdict` (`ACCEPT` or `REJECT`), `output` (object, empty on REJECT).

Suites have1..512 unique cases and1..128 unique sources; rule/source lists have
1..32 unique entries. All references must resolve. Identifiers are ASCII alphanumeric
followed by alphanumeric, dot, underscore or hyphen, at most128 bytes. Complete
suite/input/observation documents are bounded to4MiB, nesting64, total16384 object
members. Source URI max2048 bytes; reference/derivation max4096. These are tooling
limits, **not replacement bounds for SAGE's16MiB wire schema**. `json.syntax` checks
syntax within these tooling limits, not JCS serialization or every protocol schema.

JSON validation precedes struct decoding: duplicate names after escape decoding,
invalid UTF-8, unpaired surrogates, BOM, nonfinite numbers, negative zero (including
negative underflow), trailing data and unknown/missing metadata are errors. Syntax
checks intentionally retain number tokens; they do not silently convert numbers to
integers or claim a general RFC8785 canonicalizer. Changing a loaded suite before
Run is rejected, preventing the original file hash from describing altered answers.

Supported reference operations:

| Operation | Input object | ACCEPT output |
|---|---|---|
| `sha256` | `data_hex` | `sha256_hex` |
| `hkdf-sha256` | `ikm_hex`, `salt_hex`, `info_hex`, `length` in0..8160 | `prk_hex`, `okm_hex` |
| `base64url-raw.decode` | `encoded` | `data_hex` |
| `json.syntax` | `document_hex` | `valid`:true |

Hex is lowercase, even-length, without a prefix. Input field names/types are exact.
REJECT is an observed invalid input, with empty output. Unknown operation names
return UNSUPPORTED, never PASS. Primitives use Go's standard SHA-256/HMAC/base64/JSON
machinery; HKDF construction is local and checked against independently published
answers. No production cryptographic service is exposed.

## External process contract

The operator selects an executable using `-adapter` and optional repeated
`-adapter-arg`; no command comes from a fixture and no shell is used. Unix process
groups are required for this initial adapter implementation. A fresh process handles
each case; stateful multi-step operations use the separate [schema2 scenario contract](stateful-scenarios.md).

stdin contains exactly one object, with no expected values:

```json
{"schema_version":1,"protocol_version":"0.10.0","profile":"primitive-foundation","case_id":"sha256-abc","operation":"sha256","input":{"data_hex":"616263"}}
```

stdout is exactly one observation (whitespace after it is allowed):

```json
{"schema_version":1,"case_id":"sha256-abc","verdict":"ACCEPT","output":{"sha256_hex":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}
```

`verdict` is ACCEPT, REJECT or UNSUPPORTED. Output is an object, empty for the latter
two. stdout must contain no logs; stderr is bounded to64KiB, stdout to4MiB. Process
failure, timeout, malformed output, duplicate fields or wrong case correlation is
FAIL even if the fixture expects REJECT. The default deadline is5s per case; maximum
1m. Timeout kills the process group; inherited pipe waits are also bounded. This
is resource control for a trusted adapter, **not a sandbox against an adversarial
binary that escapes its group, reads files or uses the network**.

The executable SHA-256 is recorded and checked between cases. This detects ordinary
replacement, not a hostile-host race, modified interpreter/dependency, or malicious
code loaded dynamically. Pin/build adapters under trusted administration. Subject
name/revision are operator-supplied attribution, not remote attestation. Synthetic
public fixture input should be the only data passed to adapters.

For in-process `Adapter` implementations, the caller must honor context cancellation;
Go cannot forcibly stop arbitrary in-process code. Use `Process` for bounded process
execution. `ReadRequest` is provided for a strict adapter-side parser.

## Report semantics

Report schema1 records protocol/profile, suite id and exact file SHA-256, runner
version/runtime/OS/architecture/time, subject name/revision/kind and executable hash
when available, source definitions, scope, counts, and per-case results. Each result
includes rule/source IDs and derivation, input SHA-256, actual serialized adapter
request SHA-256, frozen expected verdict/output, actual observation when valid,
PASS/FAIL/UNSUPPORTED/NOT_RUN, a diagnostic reason and elapsed milliseconds.

`input_sha256` covers the raw JSON input bytes stored in the suite, not JCS bytes.
`adapter_request_sha256` covers the compact JSON envelope actually sent. The file
hash pins provenance/expectations as well as inputs. No state/effect counters are
invented for these stateless primitive operations; such evidence belongs to future
state/host adapters.

Output comparison ignores object member order, preserves array order and number
**token spelling**, and compares strings/booleans exactly. Thus1 and1.0 differ in
this initial tooling contract. Current published answers use binary hex strings.
A PASS means expected and observed answers match for this case. It does not mean
an entire referenced rule, profile, deployment or all386 planned cases passed.

Overall FAIL if any case fails; otherwise INCOMPLETE if any is UNSUPPORTED/NOT_RUN;
otherwise PASS. Selection keeps unselected cases as NOT_RUN, so a partial run never
looks complete. Unknown/duplicate selected IDs are configuration errors. Empty suites
are invalid. Report file output uses a temporary file and atomic rename; writing
errors return exit2, and suite/report path aliases are rejected. stdout always contains
JSON on a completed run. Report files are local, unsigned evidence, not certificates.
