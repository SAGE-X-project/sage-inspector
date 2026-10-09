# ADK separate-account host qualification

This observation runs the assembled `sage-adk` hosts at
`ccc053c898ac83d741c7f667efe48c964f6b7532` with the public Go core module
`v1.5.3-0.20261008173148-7e8a0790d57a` (`7e8a0790d57ae709f8efee237db94bd4995d65ee`)
on a Linux arm64 runner. The frozen SAGE 0.10.0 source remains
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It extends the earlier
[host assembly preparation](adk-host-preparation.md) with an executed run; it does
not change that report, the runtime test observation or any historical verdict.

## What runs

The [observer](../scripts/inspect_adk_host_qualification.py) requires a clean exact
ADK checkout, builds `adk-signer`, `adk-approve` and the test-only qualification
program with Go 1.26.8, and runs the pinned
`core/guardhost/testdata/qualification/run-linux.sh`:

| Account (uid:gid) | Process |
| --- | --- |
| 1001:2001 | Signer A: Alice's Ed25519 key for intent, result and transport domains, serving only uid 1004 |
| 1002:2002 | Signer B: Bob's Ed25519 key for result and transport domains, serving only uid 1003 |
| 1003:2002 | Receiver host: `guardhost.OpenReceiver`, no capture of the caller's original |
| 1004:2001 | Caller host: `guardhost.OpenCaller` and one `Call` |
| 1005:1005 | Test operator: creates and signs the policy approval |

Each account has its own state directory and artifact copy. Three checks confirm
that the caller cannot read signer A's key, the receiver cannot read the caller's
state and the receiver cannot enter signer A's socket directory. After the
360-second replay quarantine, the caller's own policy refuses unapproved arguments
(`2+4`) before issuance, then the approved `2+3` call returns the verified output
`{"output":5,"success":true}` over private native MCP on loopback TCP. The receiver
is still running afterwards and stops on SIGTERM. A continuous wall-clock
observation over the whole run must report no backward step, because the host
clock refuses any regression.

## Signer-held KEM key observation

A second, separate observation pins ADK `8111a00c964c9db3c7be4580fbe5308d4f8505b5`
with Go core `c0bac1cb5c6ef7acdbdedcb89dc47c394b473705`
(`v1.5.3-0.20261009000821-c0bac1cb5c6e`) and is saved as
[adk-host-qualification-kem-custody.json](evidence/adk-host-qualification-kem-custody.json).
Signer B also holds Bob's X25519 KEM key with the `kem` role, and the receiver
uses `NewProtectedCompletionEndpoint010`, so the receiver process holds neither a
signing nor a KEM private key. A fourth isolation check confirms the receiver
account cannot read that KEM key. The signer returns one X25519 shared value per
handshake, which lets the receiver derive that handshake's secrets; this protects
the long-term key, not the sessions of a compromised receiver. All other scope
items and limits below apply unchanged. The first report keeps its own revision,
line set and `RECEIVER_HOST_PROCESS` KEM scope.

## Initiator-only caller observation

A third observation pins ADK `c660003025038ce086a22fbd3cc56152917f88a0` with Go
core `6971de244ed87e0803f256d1616e22044d68afa8`
(`v1.5.3-0.20261009025910-6971de244ed8`) and is saved as
[adk-host-qualification-initiator-only.json](evidence/adk-host-qualification-initiator-only.json).
The caller opens an initiator-only core host (`OpenMCPClientHost`) for its call
instead of a full host with an unused admission gate, ledger, executor, policy
and result signer, so it signs no results and signer A serves only the intent
and transport roles. KEM custody, isolation checks, expected lines and every
other scope item match the signer-held KEM key observation; the earlier reports
keep their own revisions and scope.

## Scope and limits

`SEPARATE_ACCOUNT_QUALIFICATION_OBSERVED` covers only this run. The Registry
Source is a local JSON file whose readiness flags are asserted, and the calculator
measurement accepts any snapshot; IdentityAndReadiness and MeasuredComponent remain
`NOT_BOUND`. The operator key is generated for the run. All accounts share one
kernel; this is not hardware custody, attestation or sandboxing. Bob's X25519 KEM
private key stays in the receiver process. The refused call shows the caller's
issuance policy, not a receiver-side refusal. The thirteen deployed host controls
remain `NOT_RUN`, the 21 Registry mapping items stay open, and full conformance
remains `NOT_ESTABLISHED`.

On Docker Desktop for macOS the VM wall clock stepped backward by a few
milliseconds about once a minute, so the receiver failed closed before the
quarantine ended. That environment cannot host this run; the GitHub
`ubuntu-24.04-arm` runner observed no backward step.

## Reproduction

Saved-evidence checks run anywhere:

```sh
python3 -B scripts/inspect_adk_host_qualification.py
python3 -B scripts/inspect_adk_host_qualification.py --revision ccc053c898ac83d741c7f667efe48c964f6b7532
python3 -B scripts/test_adk_host_qualification.py
```

A fresh observation needs Linux arm64, passwordless `sudo`, `setpriv`, Go 1.26.8,
the pinned clean ADK checkout and downloaded public modules, and about eight
minutes:

```sh
python3 -B scripts/inspect_adk_host_qualification.py \
  --adk-root /path/to/sage-adk --revision c660003025038ce086a22fbd3cc56152917f88a0 \
  --output /tmp/new-adk-host-qualification.json
```

The [workflow](../.github/workflows/adk-host-qualification.yml) checks the saved
report and refusal units, then performs a fresh run and uploads its report. A
saved report is a review record, not a signed attestation; a log fabricated in its
entirety can satisfy the format checks.
