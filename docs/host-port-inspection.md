# Protected host-port inspection controls

The [host-port inventory](../verification/0.10.0/host-port/cases.json)
links nine trusted host ports to 13 independently stated checks. Every check
anchors an existing 0.10.0 normative parent or MCP case. These are supplemental
inspection controls, not new protocol rules or additional parent cases.
The authoritative [spec reconciliation](https://github.com/SAGE-X-project/sage-spec/blob/f97378cde7f29006520299c4246d2a50a429545f/verification/host-port-reconciliation.md)
keeps the 489-parent baseline and all wire, trust and version behavior unchanged.

The inventory pins the normative source commit and SHA-256 of the Agent/MCP
profile and traceability map. It also pins the informative host-port design
and reconciliation documents at `sage-spec`
`f97378cde7f29006520299c4246d2a50a429545f`. The checker rejects a
wrong rule/case link, an unrepresented port, a changed source file, or an
observation without exact subject and observer revisions. Run:

```sh
python3 -B scripts/test_host_port_contract.py
python3 -B scripts/host_port_contract.py --spec-root ../sage-spec
```

Without a selected host and independent observer, all 13 controls report
`NOT_RUN`. A bounded observation that matches the expected state and records
zero *new* protected effects is at most `PARTIAL`; a conflicting state or new
effect reports `FAIL`. This checker never returns `PASS`. It checks reported
facts and source links, not whether an observer truly covers every route or
whether a binary isolates credentials. The existing complete-case evidence
checker must still assess actual normative source lines and independent
deployment evidence before a parent can pass.

The checks focus on exact pre-expansion capture, independent local policy,
role-bound signing keys, measured loaded code, no arbitrary signing route,
identity-preserving retry, close/reservation order, final argument equality,
direct-route isolation, required-hook failure, gate timeout and authenticated
result release. The scenarios use inert observations and contain no executable
host-bypass or vulnerability reproduction code. Product hook names are not
portable protocol events; a deployed Claude Code or Codex adapter must map its
own actual routes and failure behavior to these trusted-host obligations.
Existing `EXEC-01..09`, MSET/MOWN and INS-11 verdicts are unchanged.

## Public core API evidence

The [nine-port API audit](evidence/host-public-api.md) separately checks public
Go/Rust compiler access and records the protected intent issuance and private
MCP assembly gaps. It does not provide independent effect observations for
these thirteen controls. All controls without a pinned host remain `NOT_RUN`;
compilation evidence cannot promote a control or a complete normative case.
