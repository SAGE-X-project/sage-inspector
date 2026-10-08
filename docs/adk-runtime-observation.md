# Pinned ADK test execution observation

The [runtime report](evidence/adk-runtime.json) records fresh execution of reviewed
`sage-adk` tests at `57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e`, using the public
Go core module `v1.5.3-0.20261008045438-f1a840bbc9c7` at
`f1a840bbc9c717564bd035e19c73f437a61e4a00`. The normative source remains
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. This adds execution evidence without
changing the seven preceding ADK source catalogs, their reports or any prior
runtime verdict. It selects no Agent or Registry deployment.

`PINNED_ADK_TESTS_PASSED` means the reviewed Go tests actually ran with
`-race`, `-count=1`, `-parallel=1` and finite timeouts. It does not mean an
independent protocol oracle accepted network messages. The
[execution catalog](../verification/0.10.0/adk-runtime/catalog.json) fixes all
444 tracked source files and the selected test commands. The
[Inspector runner](../scripts/inspect_adk_runtime.py) requires a clean exact
checkout, rejects untracked or ignored compiler inputs, disables workspaces,
and preserves the raw JSON/stdout and stderr with hashes. It verifies the
expected public core module version/checksums without replacement and runs
`go mod verify` before and after each group, then rechecks source files.

## Executed groups

| Group | Selection | Observed result |
| --- | --- | --- |
| `units` | Original capture, approved operation, compiled calculator, clock and Registry-bound signing providers. | 43 top-level tests; 229 leaf tests. |
| `native` | Three benign root paths, terminal handoff refusal, eight ordinary worker refusals, five admitted-hop paths, five independently approved-hop paths and shared clock sampling. | 8 top-level tests; 23 leaf tests, of which one is a clock unit and 22 use native runtime fixtures. |
| `public-consumer` | External module with durable original capture, shared clock and three benign public native root paths. | 5 tests, including 3 native runtime fixtures. |

The total is **56 top-level tests and 257 leaf tests**, including 25 selected
native runtime fixtures. A parent test is not added to its child count. These
are Go test identities, not 257 normative cases or new Inspector requirements.
The consumer module replaces only the ADK under review; its core dependency is
a pinned public module. Legacy A2A tests, an LLM, remote chains, real user tools
and attack-capable reproduction programs are outside this selected run.

The native tests use genuine signed/encrypted localhost exchanges and harmless
fixed arithmetic. Reviewed assertions cover actual root capture, independent
local policy, approved loaded calculator, native admitted-parent authority,
child signing/journal handoff, one effect and verified terminal delivery.
Ordinary policy/measurement/retirement/upstream-authority and callback/output
failure scenarios refuse. Their complete implementation and assertion details
remain in the pinned ADK sources; the runner does not rewrite expectations.

Approved-hop issuer/receiver bindings are co-located in the ADK test process.
Registry, key custody, original ownership and measurement assurance are local
fixtures. The compiled calculator still requires a synthetic measurement
provider in these tests. Process or measurement isolation, a production loader,
a selected blockchain Source and a selected Agent executable/configuration are
not supplied. Test lifecycle validation is not separate cryptographic
interpretation of captured frames. The earlier
[native cross-core hop observation](evidence/hop-execution.md) provides separate
bounded artifact/cryptographic checks and retains its distinct scope.

## Evidence validation

Saved evidence is checked for exact command/module/source scope and complete
per-package/per-test run and completion events. Every selected top-level test
and all eighteen named children of the native scenario groups must run and pass.
Skipped, failed, duplicate, truncated, foreign, cached or race-warning results
are refused, as are successful-looking logs paired with a failed process exit.
Go can place literal slashes inside a single `t.Run` label; validation requires
an actual running ancestor without inventing intermediate run events.

The 23 artifact refusal units change only saved test traces, metadata and mocks.
They start no malicious peer or attacker program. A saved report is not a signed
attestation: hashes and event consistency cannot establish the truth of a trace
fabricated in its entirety. Fresh observation assumes a trusted compiler,
runner/environment and quiescent inspected source/cache. This result is not a
Registry Snapshot, admission token or permission to process a message.

Recheck the saved observation and refusal units:

```sh
python3 -B scripts/inspect_adk_runtime.py
python3 -B scripts/test_adk_runtime.py
```

For fresh execution, use Go 1.26.8, a clean ADK checkout at the pin above and
cached public dependencies for both its root and `verification/library-consumer`
modules:

```sh
python3 -B scripts/inspect_adk_runtime.py \
  --adk-root /path/to/sage-adk --output /tmp/adk-runtime.json
```

The [workflow](../.github/workflows/adk-runtime.yml) repeats saved evidence and
refusal checks, fetches public dependencies, then performs all three fresh
race-enabled groups. The thirteen deployed-host controls, deployment-bound hop
execution, 21 blockchain Registry mapping requirements, full-case gates and
INS-11 remain open. Full conformance remains `NOT_ESTABLISHED`. Continue actual
Registry and protected host/provider selection and deployment observation in
the approved order; later contract upgrades, demos and A2A/DID changes stay in
their existing stages.
