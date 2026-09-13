# Foundation implementation verification

Date: 2026-09-14. Scope: new0.10.0 primitive fixture/adapter/report pipeline.
This document records observed checks, not full SAGE conformance.

## Delivered

- Core-independent `pkg/conformance`, standalone `cmd/sage-conformance` and CLI.
- Versioned strict suite loader with source attribution, immutable expectations,
  duplicate/malformed input rejection and bounded resources.
- In-process reference primitives plus an explicit bounded Unix executable adapter.
  Expected answers never go into adapter stdin.
- PASS/FAIL/UNSUPPORTED/NOT_RUN reporting, incomplete aggregate status, input/request/
  suite hashes, subject identity and expected/actual results.
-26 frozen cases and a clearly labelled same-reference-code process adapter example.

The old core-linked packages/command and go.mod/go.sum are unchanged. A new Makefile
build/test target avoids importing the legacy SAGE dependency. No sage-spec vector
or386-case plan was relabelled as executed; these are narrower foundation fixtures.

## Checks actually run

| Check | Observation |
|---|---|
| `go test -race ./pkg/conformance ./internal/conformancecli ./cmd/sage-conformance ./examples/reference-adapter` | Passed, including malformed/duplicate suite inputs, post-load mutation, missing evidence, wrong correlation, process failure/deadline/oversized output and CLI report/exit behavior |
| `go vet` on the same new package paths | Passed |
| Build standalone runner and example adapter | Passed |
| Default reference CLI |26 PASS,0 FAIL,0 UNSUPPORTED,0 NOT_RUN; exit0 |
| Explicit process example |26 PASS; exit0; exercises process transport, not independent second-core correctness |
| Select only hkdf-a1 |1 PASS,25 NOT_RUN; aggregate INCOMPLETE; exit3 |
| Alter one stored expected HKDF answer in a temporary fixture |1 FAIL; exit1 |
| Change one operation to an unknown operation in a temporary fixture |1 UNSUPPORTED; aggregate INCOMPLETE; exit3 |
| Dependency listing for standalone runner | No `github.com/sage-x-project/sage/` imports |

Commands used `GOCACHE=/private/tmp/sage-inspector-go-cache` and `GOPROXY=off` for
writable isolated cache and no dependency fetching. An initial default-cache build
was blocked by filesystem permissions and then rerun successfully with that cache.
The race detector's child-process exit delay required a sufficiently long successful
adapter-test deadline; explicit hung-process tests still use a short bounded deadline.

Captured evidence: [reference report](evidence/foundation-reference.json),
[process adapter demo report](evidence/adapter-demo.json). Reports identify actual
binary hashes; `dev` is an uncommitted build version, not a published release.
Their suite SHA-256 pins the actual bundled fixture. No report is signed or certified.

## Existing-suite limitation

A broader `go test -race ./...` attempt could not load the existing pinned SAGE module
`v1.5.3-0.20260912042550-5ab9c7e46ef3` in the current offline/sandbox cache. The failure
was in the historical `pkg/inspect` and `cmd/sage-inspector` dependency setup; no
all-repository test pass is claimed. The new command deliberately avoids that module,
and every changed/new Go package was built, vetted and race-tested independently.
No dependency version was changed to conceal the baseline issue.

## Remaining work

Actual Go/Rust implementation adapters, independently checked custom HPKE schedule
vectors, session/registry and Execution Guard state/fault fixtures, general JCS
canonicalization and host isolation observations remain future work. Reference JSON
syntax checks have tooling bounds and do not claim all protocol-schema validation.
The runner is not a sandbox for untrusted adapter binaries and does not prove source
provenance merely by displaying a URI. A fixture PASS cannot certify a whole rule,
protocol, deployment or the absence of vulnerabilities.
