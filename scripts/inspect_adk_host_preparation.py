"""Record a pinned host assembly plan; this query never authorizes execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'verification/0.10.0/adk-host-preparation/catalog.json'
CATALOG_SHA256 = '3bee57760674972d137066393dd00857509299b5bc94728ba1449218bf5aa587'
REPORT = ROOT / 'docs/evidence/adk-host-preparation.json'
RUNTIME_CATALOG = ROOT / 'verification/0.10.0/adk-runtime/catalog.json'
RUNTIME_CATALOG_SHA256 = '90787e76fdd12948b19dce7a4cc9f93f485a9e3019ec512a9a63c686186ad2ad'
CONTROLS = ROOT / 'verification/0.10.0/host-port/cases.json'
ADK_REVISION = '57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e'
NORMATIVE_REVISION = '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9'
MAX_JSON = 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def strict_json(raw):
    require(len(raw) <= MAX_JSON, 'bounded JSON required')
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate JSON member')
            obj[key] = value
        return obj
    def constant(_):
        raise ValueError('nonfinite JSON number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=constant)


def read_json(path):
    with Path(path).open('rb') as stream:
        return strict_json(stream.read(MAX_JSON + 1))


def catalogs():
    raw = CATALOG.read_bytes()
    require(sha(raw) == CATALOG_SHA256, 'host preparation catalog drift')
    review = strict_json(raw)
    raw = RUNTIME_CATALOG.read_bytes()
    require(sha(raw) == RUNTIME_CATALOG_SHA256, 'complete ADK source catalog drift')
    sources = strict_json(raw)
    raw = CONTROLS.read_bytes()
    require(sha(raw) == review['host_controls_sha256'], 'host controls drift')
    controls = strict_json(raw)
    require(review['adk_revision'] == sources['adk_revision'] == ADK_REVISION and
            review['normative_source_revision'] == controls['normative_source_revision'] == NORMATIVE_REVISION,
            'source revision mismatch')
    return review, sources, controls


def git(root, *args):
    result = subprocess.run(['git', *args], cwd=root, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    return result.stdout


def source_at(root, sources, review):
    root = Path(root).resolve(strict=True)
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == ADK_REVISION,
            'unreviewed ADK revision')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all').strip(),
            'ADK checkout must be clean')
    paths = git(root, 'ls-files', '-z').decode().split('\0')[:-1]
    require(sorted(paths) == sorted(sources['source_sha256']), 'ADK tracked source set drift')
    for path in paths:
        require(sha((root / path).read_bytes()) == sources['source_sha256'][path],
                'ADK source content drift')
    ignored = git(root, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').decode().split('\0')[:-1]
    require(not any(Path(p).suffix in ('.go', '.c', '.h', '.s', '.S', '.syso', '.mod', '.sum')
                    for p in ignored), 'ignored compiler inputs')
    for row in review['source_anchors']:
        raw = (root / row['path']).read_bytes()
        require(sha(raw) == row['sha256'] and raw.count(row['anchor'].encode()) == 1,
                'reviewed provider anchor drift')
    return root


def expected():
    review, sources, controls = catalogs()
    return {
        'schema_version': 1,
        'status': 'HOST_PREPARATION_RECORDED',
        'adk_revision': ADK_REVISION,
        'normative_source_revision': NORMATIVE_REVISION,
        'catalog_sha256': CATALOG_SHA256,
        'complete_source_catalog_sha256': RUNTIME_CATALOG_SHA256,
        'source_file_count': len(sources['source_sha256']),
        'source_anchors': review['source_anchors'],
        'integration_target': 'sage-adk',
        'planned_effect': review['planned_effect'],
        'assembly_order': review['assembly_order'],
        'excluded_routes': review['excluded_routes'],
        'provider_requirements': review['provider_requirements'],
        'host_controls': [{'id': case['id'], 'port': case['port'],
                           'source_case_id': case['source_case_id'], 'status': 'NOT_RUN'}
                          for case in controls['cases']],
        'scope': {'query': 'PINNED_SOURCE_ASSEMBLY_REVIEW',
                  'source_semantics_proven': False,
                  'deployment_configuration': 'NOT_SELECTED',
                  'registry_binding': 'UNRESOLVED',
                  'dispatch_authorization': 'NOT_GRANTED',
                  'connection_authorization': 'NOT_GRANTED',
                  'host_execution': 'NOT_RUN',
                  'full_conformance': 'NOT_ESTABLISHED'},
    }


def check_report(value):
    require(canonical(value) == canonical(expected()), 'preparation report mismatch')
    return value


def observe(root):
    review, sources, _ = catalogs()
    checked = source_at(root, sources, review)
    value = expected()
    # Repeat after constructing the report; this still requires quiescent trusted storage.
    source_at(checked, sources, review)
    return check_report(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adk-root', type=Path)
    parser.add_argument('--check', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        require(args.adk_root is not None or args.output is None,
                'fresh output requires an exact ADK source checkout')
        value = observe(args.adk_root) if args.adk_root is not None else check_report(read_json(REPORT))
        if args.check is not None:
            require(canonical(check_report(read_json(args.check))) == canonical(value),
                    'saved and fresh preparation differ')
        if args.output is not None:
            # Exclusive creation leaves existing/historical output intact, including after failure.
            with args.output.open('xb') as stream:
                stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b'\n')
        print('HOST_PREPARATION_RECORDED: 9 provider bindings required; execution NOT_GRANTED')
        return 0
    except (ValueError, OSError, subprocess.SubprocessError):
        print('host preparation refused; no new successful observation', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
