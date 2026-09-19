"""Audit MCP setup design prerequisites; never claim an authenticated handshake."""
import argparse
import json
from pathlib import Path
import subprocess
from inspect_guard_binding import exact, load, require, sha
from inspect_guard_integration import ROOT, CONTRACT as INTEGRATION, audit as integration_audit, read, digest

CONTRACT = 'verification/0.10.0/mcp-setup-review.json'
EXTERNAL = {
    'lifecycle': 'https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle',
    'transports': 'https://modelcontextprotocol.io/specification/2025-06-18/basic/transports',
}
SUPPORT = {'go': 'pkg/agent/guard010/mcp.go', 'rust': 'src/guard010/mcp.rs'}
DECISIONS = ('bootstrap', 'readiness', 'capabilities', 'notification-carriage', 'reconnect', 'http-mapping')


def validate(c, root=ROOT):
    exact(c, ('schema_version', 'kind', 'sage_version', 'mcp_baseline', 'status',
              'integration_sha256', 'references', 'support_sources', 'decisions'))
    require(type(c['schema_version']) is int and c['schema_version'] == 1, 'schema version')
    require(c['kind'] == 'mcp-setup-design-review' and c['sage_version'] == '0.10.0'
            and c['mcp_baseline'] == '2025-06-18', 'review scope')
    require(c['status'] == 'SPEC_DECISION_REQUIRED', 'review cannot certify setup')
    require(c['integration_sha256'] == sha(read(root, INTEGRATION)), 'integration revision changed')
    require(c['references'] == EXTERNAL, 'versioned primary references changed')
    exact(c['support_sources'], SUPPORT)
    for lang, path in SUPPORT.items():
        entry = c['support_sources'][lang]
        exact(entry, ('path', 'sha256'))
        require(entry['path'] == path, 'unexpected source')
        digest(entry['sha256'], 64)
    require(type(c['decisions']) is list and len(c['decisions']) == len(DECISIONS), 'decision count')
    require([x['id'] for x in c['decisions']] == list(DECISIONS), 'decision order or membership')
    for row in c['decisions']:
        exact(row, ('id', 'status', 'finding', 'proposal', 'required_evidence'))
        require(row['status'] == 'OPEN', 'unresolved decision promoted')
        for key in ('finding', 'proposal'):
            require(type(row[key]) is str and 30 <= len(row[key]) <= 2000, 'missing review rationale')
        evidence = row['required_evidence']
        require(type(evidence) is list and 2 <= len(evidence) <= 6 and all(
            type(v) is str and 15 <= len(v) <= 400 for v in evidence), 'missing acceptance evidence')
        require(len(set(evidence)) == len(evidence), 'duplicate evidence')
    return c


def audit(root=ROOT, core_roots=None):
    c = validate(load(read(root, CONTRACT)), root)
    base = integration_audit(root, core_roots)
    identity = {}
    for lang, entry in c['support_sources'].items():
        if lang not in (core_roots or {}):
            identity[lang] = 'NOT_CHECKED'
        else:
            require(sha(read(core_roots[lang], entry['path'])) == entry['sha256'], 'support source mismatch')
            identity[lang] = 'SOURCE_IDENTITY_VERIFIED'
    return dict(kind='mcp-setup-readiness', review_audit='PASS', status=c['status'],
                authenticated_setup='NOT_IMPLEMENTED', actual_core_execution=False,
                conformance='NOT_ESTABLISHED', lifecycle=base['lifecycle'],
                contract_sha256=sha(read(root, CONTRACT)), integration_sha256=c['integration_sha256'],
                reviewed_cores=base['reviewed_cores'], source_identity=base['source_identity'],
                support_source_identity=identity, references=c['references'], decisions=c['decisions'],
                scope='Pinned source and design review only; CLI execution is not MCP negotiation evidence.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--go-root', type=Path)
    p.add_argument('--rust-root', type=Path)
    a = p.parse_args()
    try:
        out = a.output.resolve()
        require(out != ROOT and not out.is_relative_to(ROOT/'docs/evidence'), 'preserve historical evidence')
        require(not out.exists(), 'output already exists')
        roots = {k: v.resolve() for k, v in [('go', a.go_root), ('rust', a.rust_root)] if v is not None}
        report = audit(core_roots=roots)
        out.mkdir(parents=True, exist_ok=False)
        (out/'contract.json').write_bytes(read(ROOT, CONTRACT))
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        p.exit(2, 'setup review error: '+str(error)+'\n')
    print('Review audit PASS; authenticated setup NOT_IMPLEMENTED; specification decisions required.')
    return 3

if __name__ == '__main__':
    raise SystemExit(main())
