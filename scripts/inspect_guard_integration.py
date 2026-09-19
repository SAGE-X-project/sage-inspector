"""Audit integration prerequisites; source identity is never execution evidence."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from inspect_guard_binding import exact, load, require, sha

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'verification/0.10.0/guard-integration-contract.json'
SOURCES = tuple('verification/0.10.0/snapshot/' + x for x in (
    'profiles/agent-mcp-security.md', 'spec/09-registry.md', 'spec/08-transport.md'))
BOUNDARIES = {
    'source': ('deployment', []),
    'authority': ('core-adapter', ['source']),
    'authorization': ('host', []),
    'transport': ('transport-adapter', ['authority']),
    'recovery': ('host', ['authorization']),
    'host': ('host', ['authority', 'authorization', 'transport', 'recovery']),
}
FILES = {
    'go': ('pkg/agent/registry010/gate.go', 'pkg/agent/guard010/verify.go',
           'pkg/agent/guard010/dispatch.go', 'pkg/agent/guard010/client.go',
           'pkg/agent/guard010/mcp_rpc.go', 'pkg/agent/guard010/mcp_session.go', 'pkg/agent/guard010/registry.go', 'pkg/agent/hpke/completion010.go'),
    'rust': ('src/registry010/mod.rs', 'src/guard010/mod.rs',
             'src/guard010/dispatch.rs', 'src/guard010/client.rs',
             'src/guard010/mcp_rpc.rs', 'src/guard010/mcp_session.rs', 'src/guard010/registry.rs', 'src/hpke/completion010.rs'),
}


def digest(value, size):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value), 'invalid digest')


def read(root, relative):
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()), 'source escapes checkout')
    require(not path.is_symlink(), 'source is a symlink')
    raw = path.read_bytes()
    require(len(raw) <= 1024 * 1024, 'source size limit')
    return raw


def validate(c, root=ROOT):
    exact(c, ('schema_version', 'protocol_version', 'kind', 'conformance',
              'lifecycle', 'sources', 'reviewed_cores', 'boundaries'))
    require(type(c['schema_version']) is int and c['schema_version'] == 1, 'schema version')
    require(c['protocol_version'] == '0.10.0' and c['kind'] == 'guard-integration-review', 'contract kind')
    require(c['conformance'] == 'NOT_ESTABLISHED', 'source review cannot certify conformance')
    exact(c['lifecycle'], ('status', 'scenarios'))
    require(c['lifecycle']['status'] == 'NOT_RUN' and type(c['lifecycle']['scenarios']) is int
            and c['lifecycle']['scenarios'] == 37, 'lifecycle promotion')
    exact(c['sources'], SOURCES)
    for path, expected in c['sources'].items():
        digest(expected, 64)
        require(sha(read(root, path)) == expected, 'spec hash mismatch: ' + path)
    exact(c['reviewed_cores'], FILES)
    for language, core in c['reviewed_cores'].items():
        exact(core, ('revision', 'evidence', 'files'))
        digest(core['revision'], 40)
        require(core['evidence'] == 'SOURCE_REVIEW_ONLY', 'source review promoted to runtime')
        exact(core['files'], FILES[language])
        for value in core['files'].values():
            digest(value, 64)
    require(type(c['boundaries']) is list and len(c['boundaries']) == len(BOUNDARIES), 'boundary count')
    seen = set()
    for row in c['boundaries']:
        exact(row, ('id', 'requires', 'owner', 'title', 'contract', 'failure', 'required_evidence', 'status'))
        ident = row['id']
        require(type(ident) is str and ident in BOUNDARIES and ident not in seen, 'unknown or duplicate boundary')
        owner, dependencies = BOUNDARIES[ident]
        require(row['owner'] == owner and row['requires'] == dependencies, 'ownership or dependency mismatch')
        require(set(dependencies) <= seen, 'dependency order')
        require(row['status'] == 'INTEGRATION_NOT_VERIFIED', 'unverified integration promoted')
        for key in ('title', 'contract', 'failure'):
            require(type(row[key]) is str and 15 <= len(row[key]) <= 2000, 'missing boundary description')
        evidence = row['required_evidence']
        require(type(evidence) is list and 3 <= len(evidence) <= 8
                and all(type(x) is str and 15 <= len(x) <= 256 for x in evidence), 'missing evidence requirements')
        require(len(set(evidence)) == len(evidence), 'duplicate evidence requirement')
        seen.add(ident)
    return c


def audit(root=ROOT, core_roots=None):
    raw = read(root, CONTRACT)
    c = validate(load(raw), root)
    identities = {}
    for language, checkout in (core_roots or {}).items():
        require(language in FILES, 'unknown core')
        checkout = checkout.resolve()
        core = c['reviewed_cores'][language]
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout,
                                           text=True, timeout=10).strip()
        require(revision == core['revision'], 'core revision mismatch: ' + language)
        for path, expected in core['files'].items():
            require(sha(read(checkout, path)) == expected, 'core source mismatch: ' + path)
        identities[language] = dict(status='SOURCE_IDENTITY_VERIFIED', revision=revision,
                                    files=core['files'])
    return dict(schema_version=1, kind='guard-integration-readiness', status='INCOMPLETE',
                contract_audit='PASS', conformance='NOT_ESTABLISHED', actual_core_execution=False,
                lifecycle=c['lifecycle'], contract_sha256=sha(raw), sources=c['sources'],
                reviewed_cores=c['reviewed_cores'], source_identity={language: identities.get(language,
                    dict(status='NOT_CHECKED')) for language in FILES}, boundaries=c['boundaries'],
                scope='Source review and prerequisite audit only; no deployment or host certification.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(output != ROOT and ROOT / 'docs/evidence' not in (output, *output.parents),
                'preserve historical evidence')
        require(not output.exists(), 'output directory already exists')
        roots = {k: v for k, v in [('go', args.go_root), ('rust', args.rust_root)] if v is not None}
        report = audit(core_roots=roots)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes((ROOT / CONTRACT).read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(2, 'integration audit error: ' + str(error) + '\n')
    print('Contract audit PASS; deployment integration INCOMPLETE; no runtime claim.')
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
