# Agent host candidate assessment

This is a source review for the next 0.10.0 host integration, not a deployed
host inspection. The [pinned source manifest](evidence/agent-host-candidate-assessment/manifest.json)
identifies the files behind each finding. The earlier
[deployment audit](agent-host-deployment-audit.md) and its eight host scenarios
remain `NOT_RUN`; full conformance remains `NOT_ESTABLISHED`.

At `sage-adk` revision `6037298b49054ed6d1784ca1a28b6318b7dc310f`,
`cmd/adk/serve.go` builds an agent with a default message handler. The agent's
`Process` method delegates to that handler. `core/tools/types.go` exposes a
tool registry whose `Execute` method invokes the selected tool; the
`examples/tools-agent/main.go` path uses it, but that file has an `examples`
build tag and is not the default `adk serve` host. A scan of tracked ADK Go
sources at this revision found no `guard010` or `execution010` reference. This
is a candidate for future integration, not an observed 0.10.0 Guard binding.

The current core assemblies also stop short of a public host boundary. Go
`sage` revision `fbd9b2169c72d62c62dcbaa2336275d08a5735a8` keeps its
`mcpHost` coordinator private. Rust `rs-sage-core` revision
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f` keeps `OwnedClient`,
`RootCapture` and `ClientPool` crate-private. Both cores expose lower-level
Guard functionality, and Inspector has run protected local request and policy
tests, but those observations do not show that an ADK process protects every
tool or other effect path.

| Integration decision | Required reviewable result |
| --- | --- |
| Select a host | Pin an executable build, configuration and ownership of all protected effect paths. Decide whether `sage-adk` is that host after the public core contract and consumer audit stabilize. |
| Capture original input | Keep the exact user request and authorization baseline outside model/plugin write authority before expansion. |
| Bind admission | Pass the same approved arguments, policy epoch, measured component instance and authenticated peer into the final Guard gate. Expose an explicit host port in each core where needed. |
| Own execution | Mediate tool, MCP, file, network and subprocess effects that the selected host claims to protect; return unsupported for paths it cannot mediate. |
| Isolate authority | Keep the signing key, approved baseline and independent effect observer outside the plugin/model trust domain. |
| Prove behavior | Run the Inspector host adapter with a pinned binary, external observer, positive control, denial cases and recovery; retain exact request, journal, effect and route-coverage evidence. |

This assessment makes no deployment verdict. The nine binding inputs listed
in the [deployment audit](agent-host-deployment-audit.md) are still absent.
No ADK executable, plugin or effect observer was started during this source
review. The existing Go internal `mcpHost` test and the 12-case protected
MCP-to-Guard policy run remain core-local evidence only. In particular, the
new policy result does not promote any of the eight deployment scenarios to
`PASS`.

The ordered [remaining-work register](remaining-work.md) stays in force:
reconcile the normative snapshot, map both core and consumer contracts, then
stabilize strict libraries and host ports before selecting and inspecting a
deployed Agent host. The later decision is which executable and effect
inventory will be the first host subject; this review does not select one.

## Native Client readiness update

At Go `8c29b785e36fe8f7d7dc9e55bd9deb036df0088f` and Rust
`c99d373b772a3fb33e166fda3e07ee7ba94414f0`, the native capture constructors
and captured Client opening entry points are public. The later
[capture and journal report](evidence/captured-client-parity.md) and
[signed result report](evidence/captured-client-results.md) independently
exercise these APIs with pinned consumers. This supersedes the earlier
crate-private `RootCapture` finding for those revisions; the full MCP host
assembly and deployed route ownership still require integration evidence.

A source recheck found `sage-adk` still at the revision above, with no tracked
Go source references to `guard010`, `execution010` or `OpenCapturedClient`.
Its message-handler and tool-registry paths therefore remain integration
candidates. The public Client evidence does not supply a protected ADK
executable or an independent host effect observer, so the host verdicts stay
`NOT_RUN`.
