"""Capture bounded record-core closure observations for SESSION-06.

This observes record refusal after explicit close, not authenticated recovery,
registry admission, persistence, or application plaintext fallback.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import same
from check_current_spec_session06_vectors import check as check_vectors, IDS


REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def requests(root):
    source = root / 'vectors/0.10.0/session-scenarios/session-close.json'
    steps = load(source.read_bytes())['steps']
    records = load((root / 'vectors/0.10.0/session-records.json').read_bytes())['cases']
    next_record = next(row for row in records if row['id'] == 'c2s-open-1')
    require(steps[5]['input'] == {'action': 'receive', 'seq': 1} and
            next_record['expected']['verdict'] == 'ACCEPT' and
            int.from_bytes(bytes.fromhex(next_record['input']['record_hex'][:16]),
                           'big') == 1, 'closed receive record source')
    create = steps[0]['input']
    controls = {'seed_hex': create['seed_hex'], 'th_hex': create['th_hex'],
                'initiator': False}
    actions = (
        ('create', 'record010.create', controls),
        ('open-before-close', 'record010.open', {
            'record_hex': steps[1]['input']['record_hex'],
            'caller_aad_hex': steps[1]['input']['caller_aad_hex']}),
        ('close', 'record010.close', {}),
        ('open-after-close', 'record010.open', {
            'record_hex': next_record['input']['record_hex'],
            'caller_aad_hex': next_record['input']['caller_aad_hex']}),
        ('seal-after-close', 'record010.seal', {
            'plaintext_hex': '00', 'caller_aad_hex': ''}),
    )
    queries = [{'schema_version': 2, 'protocol_version': '0.10.0',
                'profile': 'stateful-scenario', 'case_id': 'SESSION-06-N05',
                'step_id': step, 'operation': operation, 'input': data}
               for step, operation, data in actions]
    return sha(source.read_bytes()), queries


def project(root, responses):
    _, queries = requests(root)
    require(len(responses) == len(queries), 'closure response count')
    records = load((root / 'vectors/0.10.0/session-records.json').read_bytes())['cases']
    known = {row['input']['record_hex']: row['expected']['output']['plaintext_hex']
             for row in records if row['operation'] == 'sage.session.record.open'
             and row['expected']['verdict'] == 'ACCEPT'}
    sid = load((root / 'vectors/0.10.0/session-scenarios/session-close.json').read_bytes())[
        'steps'][0]['input']['sid']
    expected = ('ACCEPT', 'ACCEPT', 'ACCEPT', 'REJECT', 'REJECT')
    verdicts = tuple(row['verdict'] for row in responses)
    if verdicts != expected:
        return {'status': 'FAIL', 'verdicts': list(verdicts)}
    outputs = ({'session_id': sid},
               {'plaintext_hex': known[queries[1]['input']['record_hex']]},
               {}, {}, {})
    for index, row in enumerate(responses):
        require(row['output'] == outputs[index] and
                row['effects'] == {'core_open_success': int(index >= 1),
                    'core_seal_success': 0,
                    'core_close_calls': int(index >= 2)},
                'closed record releases plaintext or advances effects')
    return {'status': 'PARTIAL', 'verdicts': list(verdicts),
            'actual': {'verdict': 'REJECT', 'output': {}, 'effects': {}}}


def capture(root, executables, output):
    spec_revision = catalog(root)[0]['spec_revision']
    require(check_vectors(root) == 6, 'SESSION-06 fixture provenance')
    require(not output.exists() and not output.resolve().is_relative_to(root.resolve()),
            'new external evidence directory required')
    runner_revision = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip()
    report = {'schema_version': 1, 'spec_revision': spec_revision,
              'runner_revision': runner_revision,
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'subjects': {}, 'cases': {}}
    digest, queries = requests(root)
    wire = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n'
                   for row in queries).encode()
    for language, binary in executables.items():
        require(language in REVISIONS and binary.is_file() and
                not binary.is_symlink(), 'stateful subject executable')
        repository, revision = REVISIONS[language]
        report['subjects'][language] = {'repository': repository,
            'revision': revision, 'executable_sha256': sha(binary.read_bytes())}
        proc = subprocess.run([str(binary)], input=wire, capture_output=True,
                              timeout=15, check=False)
        require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024 and
                len(proc.stderr) <= 1024 * 1024,
                'stateful adapter failed or exceeded bound: ' + language)
        responses = [load(line) for line in proc.stdout.splitlines()]
        require(len(responses) == len(queries) and all(type(row) is dict and
                set(row) == {'schema_version', 'case_id', 'step_id', 'verdict',
                             'output', 'effects'} and
                row['schema_version'] == 2 and
                row['case_id'] == 'SESSION-06-N05' and
                row['step_id'] == query['step_id'] and
                row['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED') and
                type(row['output']) is dict
                for row, query in zip(responses, queries)),
                'stateful response identity: ' + language)
        cases = {ident: {'status': 'UNSUPPORTED',
                'reason': 'Record core does not expose this protocol boundary.'}
                 for ident in IDS}
        cases['SESSION-06-N05'] = {'scenario_sha256': digest,
            'requests': queries, 'responses': responses,
            **project(root, responses)}
        report['cases'][language] = cases
        require(sha(binary.read_bytes()) ==
                report['subjects'][language]['executable_sha256'],
                'stateful binary changed during run')
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def check(root, evidence):
    report = load((evidence / 'report.json').read_bytes())
    require(report['spec_revision'] == catalog(root)[0]['spec_revision'] and
            report['runner_sha256'] == sha(Path(__file__).read_bytes()) and
            check_vectors(root) == 6, 'stateful closure report provenance')
    digest, queries = requests(root)
    for language, (repository, revision) in REVISIONS.items():
        require(report['subjects'][language]['repository'] == repository and
                report['subjects'][language]['revision'] == revision,
                'stateful closure subject identity: ' + language)
        cases = report['cases'][language]
        require(set(cases) == set(IDS), 'stateful closure case inventory')
        for ident in IDS:
            row = cases[ident]
            if ident != 'SESSION-06-N05':
                require(row['status'] == 'UNSUPPORTED' and row['reason'],
                        'unsupported closure boundary: ' + ident)
                continue
            require(row['scenario_sha256'] == digest and
                    same(row['requests'], queries) and
                    len(row['responses']) == len(queries) and
                    all(type(response) is dict and set(response) == {
                        'schema_version', 'case_id', 'step_id', 'verdict',
                        'output', 'effects'} and
                        response['schema_version'] == 2 and
                        response['case_id'] == ident and
                        response['step_id'] == query['step_id']
                        for response, query in zip(row['responses'], queries)) and
                    same(project(root, row['responses']),
                         {key: row[key] for key in ('status', 'verdicts', 'actual')}),
                    'stateful closure observation: ' + language)
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            require(row['status'] == 'PARTIAL' and
                    same(row['actual'], fixture['expected']),
                    'stateful closure expectation: ' + language)
    return {language: {ident: row['status'] for ident, row in cases.items()}
            for language, cases in report['cases'].items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    try:
        if args.check:
            print(check(ROOT, args.check))
        else:
            require(args.go and args.rust and args.output,
                    'both binaries and output required')
            print(capture(ROOT, {'go': args.go.resolve(),
                                'rust': args.rust.resolve()}, args.output)['runner_revision'])
    except (ValueError, KeyError, TypeError, OSError,
            subprocess.SubprocessError) as error:
        print('SESSION-06 stateful evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
