"""Run bounded Go/Rust PoP-byte adapters without promoting registry conformance."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SPEC_REVISION = '5ec68684df4e449a3963724444bfba64a70b825f'
CORE_REVISIONS = {
    'go': '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
    'rust': 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
}
CASE_IDS = [
    'mllm-kem-alg-valid', 'mllm-kem-alg-case', 'mllm-kem-selection',
    'mllm-pop-exact-bytes', 'mllm-pop-duplicate-field',
    'mllm-kem-signature-reject', 'mllm-kem-type-valid', 'mllm-kem-key-length',
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=path, text=True).strip()


def case_statuses():
    return {case: {'status': 'PARTIAL' if case == 'mllm-pop-exact-bytes' else 'NOT_RUN',
                   'reason': ('Exact challenge bytes executed in both cores; proof signatures and registration were not.'
                              if case == 'mllm-pop-exact-bytes' else
                              'No complete validating Source, registration, signature, or handshake decision was executed.')}
            for case in CASE_IDS}


def observe(binary, request):
    raw = json.dumps(request, separators=(',', ':'))
    result = subprocess.run([str(binary)], input=raw, capture_output=True,
                            text=True, timeout=10, check=False)
    if result.returncode != 0:
        raise ValueError(f'adapter exited {result.returncode}: {result.stderr}')
    actual = json.loads(result.stdout)
    if actual.get('case_id') != request['case_id']:
        raise ValueError('case identity changed')
    return {'request': request, 'request_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr, 'actual': actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--go-root', required=True, type=Path)
    parser.add_argument('--rust-root', required=True, type=Path)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--rust', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT / 'docs/evidence' in (output, *output.parents):
        parser.error('preserve archived evidence')
    output.mkdir(parents=True, exist_ok=False)
    fixture = ROOT / 'vectors/0.10.0/registry-proof-0.10.0.json'
    report = {'kind': 'registry-proof010-core-byte-execution', 'status': 'RUNNING',
              'conformance': 'NOT_ESTABLISHED', 'inspector_revision': revision(ROOT),
              'spec_revision': SPEC_REVISION, 'fixture_sha256': digest(fixture),
              'core_revisions': CORE_REVISIONS, 'cases': case_statuses(),
              'observations': []}

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        assert revision(args.spec_root) == SPEC_REVISION, 'spec revision'
        for name, root in [('go', args.go_root), ('rust', args.rust_root)]:
            assert revision(root) == CORE_REVISIONS[name], name + ' core revision'
            assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=root), name + ' tracked source changed'
        assert digest(args.spec_root / 'verification/vectors/registry-proof-0.10.0.json') == digest(fixture)
        assert digest(args.go_root / 'pkg/agent/registry010/testdata/registry-proof-0.10.0.json') == digest(fixture)
        assert digest(args.rust_root / 'tests/fixtures/registry-proof-0.10.0.json') == digest(fixture)
        plan = json.loads((args.spec_root / 'verification/traceability.json').read_text())
        cases = {case['id']: case for case in plan['cases']}
        assert all(case in cases and cases[case]['evidence_status'] == 'planned_not_executed'
                   for case in CASE_IDS), 'spec case plan'
        values = json.loads(fixture.read_text())['challenge_vectors']
        assert len(values) == 2
        programs = {'go': args.go.resolve(), 'rust': args.rust.resolve()}
        for vector in values:
            request = {key: vector[key] for key in ('registry_id', 'agent_id', 'name', 'alg', 'public_key_hex')}
            request['case_id'] = vector['name']
            for name, binary in programs.items():
                observed = observe(binary, request)
                observed['subject'] = name
                report['observations'].append(observed)
                actual = observed['actual']
                assert actual == {'case_id': vector['name'], 'verdict': 'ACCEPT',
                                  'challenge_hex': vector['challenge_hex'],
                                  'challenge_sha256': vector['challenge_sha256']}, (name, actual)
                save()
        base = {key: values[0][key] for key in ('registry_id', 'agent_id', 'name', 'alg', 'public_key_hex')}
        for label, change in [('non-ascii', {'agent_id': 'agént'}),
                              ('empty-key', {'public_key_hex': ''}),
                              ('bad-hex', {'public_key_hex': '0G'})]:
            request = dict(base, case_id=label, **change)
            for name, binary in programs.items():
                observed = observe(binary, request)
                observed['subject'] = name
                report['observations'].append(observed)
                assert observed['actual'] == {'case_id': label, 'verdict': 'REJECT'}, (name, label)
                save()
        report['status'] = 'PARTIAL_BOUNDARY_PASS'
    except Exception as error:
        report.update(status='FAIL', reason=str(error))
        raise
    finally:
        save()
    print('Two exact PoP vectors and three bounded input controls passed in both cores; eight Inspector cases remain partial or unrun.')


if __name__ == '__main__':
    main()
