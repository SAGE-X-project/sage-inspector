"""Check pinned ADK syntax anchors. Never execute ADK or certify a host.

The operator supplies a trusted Inspector-built parser. The inspected checkout
must stay quiescent throughout the query. Hash and Git checks detect drift; this
is not an isolation boundary for a concurrently hostile local filesystem.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'verification/0.10.0/adk-source-inventory/catalog.json'
CATALOG_SHA = '2d0daea8502398ca08ce621053f55200ea4e1e4403e367b0b5296abdb99a2730'
ADK_REVISION = 'afa469cdd8539992185235008ac1591c74012f7f'
NORMATIVE_REVISION = '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9'
SNAPSHOTS = {
    'routes': {'path': CATALOG, 'sha256': CATALOG_SHA, 'revision': ADK_REVISION},
    'approved-operation': {
        'path': ROOT / 'verification/0.10.0/adk-approved-operation/catalog.json',
        'sha256': '5d342fc196073de169b2ebe349ead6c3032da1d5fbb119a6d7f1803d21c1b399',
        'revision': 'fb98773df57b258c29ff9c355d062158bdf56c0e',
    },
    'compiled-calculator': {
        'path': ROOT / 'verification/0.10.0/adk-compiled-calculator/catalog.json',
        'sha256': 'c6a1661827803c1160c4cafda92d16434eb30de724e06f791c3957f0fa968098',
        'revision': '1da9d02226bd690f92ccc4198638afc84579a9e8',
    },
}
KINDS = {'GUARD_NATIVE_OPT_IN', 'CAPTURE_ONLY', 'PROTECTED_PROVIDER',
         'LEGACY_UNMEDIATED', 'CONFIGURATION_ONLY', 'PROPOSAL_ONLY',
         'OUTBOUND_LLM_PROPOSAL', 'APPROVED_OPERATION_OPT_IN',
         'COMPILED_CALCULATOR_OPT_IN'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def catalog(path=None, snapshot='routes'):
    require(snapshot in SNAPSHOTS, 'unknown snapshot')
    pinned = SNAPSHOTS[snapshot]
    raw = Path(pinned['path'] if path is None else path).read_bytes()
    require(sha(raw) == pinned['sha256'], 'reviewed catalog changed')
    suite = json.loads(raw)
    contract = ROOT / 'verification/0.10.0/host-port/cases.json'
    require(sha(contract.read_bytes()) == suite['host_port_catalog_sha256'],
            'host-port catalog drift')
    require(suite['adk_revision'] == pinned['revision'] and
            suite['normative_source_revision'] == NORMATIVE_REVISION,
            'source revision drift')
    return suite


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, timeout=30)


def bounded_source(root, name):
    path = root
    for part in Path(name).parts:
        path = path / part
        require(not path.is_symlink(), 'symlink source refused: ' + name)
    require(path.is_file() and path.stat().st_size <= 2 << 20,
            'source unavailable or oversized: ' + name)
    return path.read_bytes()


def check_source(root, suite):
    root = Path(root).resolve(strict=True)
    require(git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(root),
            'source root must be the Git checkout root')
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == suite['adk_revision'],
            'ADK revision mismatch')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all').strip(),
            'ADK source is dirty or contains untracked files')
    require(not git(root, 'ls-files', '--others', '--ignored', '--exclude-standard',
                    '-z', '*.go').strip(b'\0'), 'ignored untracked Go source')
    tracked = git(root, 'ls-files', '-z').decode().split('\0')
    paths = sorted(p for p in tracked if p.endswith('.go') and not p.endswith('_test.go'))
    require(paths == sorted(suite['sources']), 'production source set drift')
    for name, digest in (suite['sources'] | suite['module_files']).items():
        require(sha(bounded_source(root, name)) == digest, 'source hash drift: ' + name)
    return root, paths


def validate_inventory(inventory, suite):
    require(set(inventory) == {'schema_version', 'kind', 'files'} and
            type(inventory['schema_version']) is int and inventory['schema_version'] == 1 and
            inventory['kind'] == 'GO_SYNTAX_INVENTORY' and
            type(inventory['files']) is list, 'closed syntax inventory')
    files = inventory['files']
    require([f['path'] for f in files] == sorted(suite['sources']), 'AST source set drift')
    for f in files:
        require(set(f) == {'path', 'sha256', 'package', 'declarations', 'initializer_calls'} and
                f['sha256'] == suite['sources'][f['path']] and
                type(f['package']) is str and bool(f['package']) and
                type(f['declarations']) is list and type(f['initializer_calls']) is list,
                'closed hashed AST source')
        for d in f['declarations']:
            require(set(d) == {'name', 'exported', 'line', 'end_line', 'calls'} and
                    type(d['name']) is str and bool(d['name']) and
                    type(d['exported']) is bool and type(d['line']) is int and
                    type(d['end_line']) is int and 0 < d['line'] <= d['end_line'] and
                    type(d['calls']) is list, 'closed declaration')
        for c in f['initializer_calls'] + [c for d in f['declarations'] for c in d['calls']]:
            require(set(c) == {'callee', 'line'} and type(c['callee']) is str and
                    bool(c['callee']) and type(c['line']) is int and c['line'] > 0,
                    'closed syntactic call')
    return {f['path']: f for f in files}


def report(inventory, suite):
    snapshots = [name for name, pinned in SNAPSHOTS.items()
                 if suite.get('adk_revision') == pinned['revision']]
    require(len(snapshots) == 1, 'unreviewed source revision')
    snapshot = snapshots[0]
    require(suite == catalog(snapshot=snapshot), 'reviewed catalog changed')
    files = validate_inventory(inventory, suite)
    routes = []
    for row in suite['routes']:
        require(row['classification'] in KINDS, 'unknown route classification')
        declarations = [d for d in files[row['path']]['declarations']
                        if d['name'] == row['declaration'] and d['line'] == row['line']]
        require(len(declarations) == 1, 'reviewed declaration missing: ' + row['id'])
        for anchor in row['calls']:
            require(declarations[0]['calls'].count(anchor) == 1,
                    'reviewed syntactic call missing: ' + row['id'])
        routes.append(dict(row, anchor_status='MATCHED'))
    result = {
        'schema_version': 1,
        'kind': 'ADK_SOURCE_ROUTE_INVENTORY',
        'protocol_version': '0.10.0',
        'normative_source_revision': NORMATIVE_REVISION,
        'adk_revision': suite['adk_revision'],
        'catalog_sha256': SNAPSHOTS[snapshot]['sha256'],
        'host_port_catalog_sha256': suite['host_port_catalog_sha256'],
        'query_status': 'AST_QUERY_EXECUTED',
        'source_file_count': len(files),
        'declaration_count': sum(len(f['declarations']) for f in files.values()),
        'syntactic_call_count': sum(len(f['initializer_calls']) +
                                   sum(len(d['calls']) for d in f['declarations'])
                                   for f in files.values()),
        'route_classification_counts': dict(sorted(Counter(r['classification'] for r in routes).items())),
        'selected_host': None,
        'host_selection': 'SELECTION_PENDING',
        'deployed_host_controls': {'count': 13, 'status': 'NOT_RUN'},
        'adk_runtime': 'NOT_RUN',
        'effect_observations': None,
        'independent_hop_execution': 'NOT_RUN',
        'full_conformance': 'NOT_ESTABLISHED',
        'routes': routes,
        'limitations': [
            'Manual route classifications; AST matching does not prove authorization or reachability.',
            'All tracked non-test Go files, including examples, generated code and all build tags, are parsed.',
            'Selected route anchors are not an exhaustive effect graph; other declarations remain unclassified.',
            'No type resolution, external dependencies, dynamically loaded plugins or reflective dispatch analysis.',
            'Nested function calls belong to the enclosing declaration; package initializer calls are separate.',
            'No ADK code, external LLM call, tool callback or deployment is executed by this query.',
            'Native protection is opt-in and depends on isolated authoritative policy, registry, custody and loader bindings.',
        ],
    }
    if snapshot in ('approved-operation', 'compiled-calculator'):
        result['limitations'] += [
            'Exact-operation rules are trusted local root configuration; parent-hop policy is separate.',
            'Factory.Load and Instance.Check remain trusted providers; snapshots and source queries do not attest actual loaded code.',
            'Binding.Tool remains a trusted native configuration capability, not a model-facing unsigned dispatcher.',
            'Artifact reading requires protected serialized administration; local gating does not establish OS isolation or durable distributed epochs.',
            'Linux/macOS and unsupported-platform sources are both parsed; build-tag selection and execution are not observed.',
        ]
    if snapshot == 'compiled-calculator':
        result['limitations'] += [
            'The calculator adapter constructs a fixed statically compiled tool; it does not load code from snapshot artifacts.',
            'Measurement.Check must establish protected verification before host image/dependency loading and retained immutable runtime identity; this query supplies no provider or deployment attestation.',
            'The same private calculator callback is an opt-in trusted capability behind native admission; direct builtin and ordinary dispatch remain unmediated.',
            'ADK unit and local runtime results with fixture Registry/measurement providers remain separate evidence; completed arithmetic can return a domain-error result.',
        ]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adk-root', type=Path, required=True)
    parser.add_argument('--parser', type=Path, required=True, help='trusted Inspector-built AST CLI')
    parser.add_argument('--snapshot', choices=sorted(SNAPSHOTS), default='routes',
                        help='exact reviewed source revision; historical routes remain the default')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', type=Path, help='require exact saved report equality')
    args = parser.parse_args()
    suite = catalog(snapshot=args.snapshot)
    root, paths = check_source(args.adk_root, suite)
    result = subprocess.run([str(args.parser.resolve(strict=True)), '--root', str(root)],
                            input=json.dumps(paths), text=True, capture_output=True, timeout=60)
    require(result.returncode == 0, 'AST query failed: ' + result.stderr[:1000])
    require(len(result.stdout) <= 32 << 20, 'AST report too large')
    output = report(json.loads(result.stdout), suite)
    check_source(root, suite)
    if args.check:
        require(output == json.loads(args.check.read_text()), 'saved source report drift')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(f"Matched {len(output['routes'])} reviewed routes across {len(paths)} source files; deployed host remains NOT_RUN")


if __name__ == '__main__':
    main()
