"""Capture bounded, retained-core SESSION-05 replay observations.

Only record authentication and replay state are observed. This is not a
transport, signature, dispatch, or concurrency adapter.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import same
from check_current_spec_session05_vectors import check as check_vectors, IDS


PATHS = {
    'SESSION-05-P': ('session-reorder-replay', (1, 3, 5, 7),
                     ('ACCEPT', 'ACCEPT', 'ACCEPT', 'REJECT')),
    'SESSION-05-N02': ('session-invalid-does-not-reserve', (1, 3),
                       ('REJECT', 'ACCEPT')),
    'SESSION-05-N03': ('session-reorder-replay', (1, 3, 7),
                       ('ACCEPT', 'ACCEPT', 'REJECT')),
}
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def requests(root, ident):
    scenario_name, indexes, _ = PATHS[ident]
    source = root / 'vectors/0.10.0/session-scenarios' / (scenario_name + '.json')
    steps = load(source.read_bytes())['steps']
    create = steps[0]['input']
    controls = {'seed_hex': create['seed_hex'], 'th_hex': create['th_hex'],
                'initiator': False}
    actions = [('create', 'record010.create', controls)]
    for number in indexes:
        row = steps[number]
        require(row['input']['action'] == 'receive', 'record receive source')
        actions.append(('open-' + str(number), 'record010.open', {
            'record_hex': row['input']['record_hex'],
            'caller_aad_hex': row['input']['caller_aad_hex']}))
    return sha(source.read_bytes()), [
        {'schema_version': 2, 'protocol_version': '0.10.0',
         'profile': 'stateful-scenario', 'case_id': ident, 'step_id': step,
         'operation': operation, 'input': data}
        for step, operation, data in actions]


def project(root, ident, responses):
    _, indexes, expected_verdicts = PATHS[ident]
    _, queries = requests(root, ident)
    create = load((root / 'vectors/0.10.0/session-scenarios' /
                   (PATHS[ident][0] + '.json')).read_bytes())['steps'][0]['input']
    records = load((root / 'vectors/0.10.0/session-records.json').read_bytes())['cases']
    known_plaintext = {row['input']['record_hex']:
        row['expected']['output']['plaintext_hex'] for row in records
        if row['operation'] == 'sage.session.record.open' and
        row['expected']['verdict'] == 'ACCEPT'}
    require(len(responses) == len(indexes) + 1 and
            responses[0]['verdict'] == 'ACCEPT' and
            responses[0]['output'] == {'session_id': create['sid']},
            'record create result')
    observed = tuple(row['verdict'] for row in responses[1:])
    accepted = 0
    for number, row in enumerate(responses):
        require(type(row['effects']) is dict and
                set(row['effects']) == {'core_open_success', 'core_seal_success',
                                       'core_close_calls'} and
                row['effects']['core_seal_success'] == 0 and
                row['effects']['core_close_calls'] == 0,
                'record-only effect counters')
        if row is not responses[0] and row['verdict'] == 'ACCEPT':
            accepted += 1
            record_hex = queries[number]['input']['record_hex']
            require(row['output'] == {
                'plaintext_hex': known_plaintext[record_hex]},
                'independent record plaintext')
        elif number > 0:
            require(row['output'] == {}, 'rejected record releases output')
        require(row['effects']['core_open_success'] == accepted,
                'record acceptance counter')
    if observed != expected_verdicts:
        return {'status': 'FAIL', 'verdicts': list(observed)}
    if ident == 'SESSION-05-P':
        actual = {'verdict': 'ACCEPT', 'output': {
            'accepted_sequences': [int.from_bytes(bytes.fromhex(
                queries[i]['input']['record_hex'][:16]), 'big')
                for i, row in enumerate(responses) if i and row['verdict'] == 'ACCEPT']},
            'effects': {}}
    elif ident == 'SESSION-05-N02':
        actual = {'verdict': 'ACCEPT', 'output': {
            'bad_tag': observed[0], 'valid_same_sequence': observed[1]},
            'effects': {}}
    else:
        actual = {'verdict': observed[-1], 'output': {}, 'effects': {}}
    return {'status': 'PARTIAL', 'verdicts': list(observed),
            'actual': actual}


def capture(root, executables, output):
    spec_revision = catalog(root)[0]['spec_revision']
    require(check_vectors(root) == 5, 'SESSION-05 fixture provenance')
    require(not output.exists() and not output.resolve().is_relative_to(root.resolve()),
            'new external evidence directory required')
    runner_revision = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip()
    report = {'schema_version': 1, 'spec_revision': spec_revision,
              'runner_revision': runner_revision,
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'subjects': {}, 'cases': {}}
    for language, binary in executables.items():
        require(language in REVISIONS and binary.is_file() and
                not binary.is_symlink(), 'stateful subject executable')
        repository, revision = REVISIONS[language]
        report['subjects'][language] = {'repository': repository,
            'revision': revision, 'executable_sha256': sha(binary.read_bytes())}
        cases = {}
        for ident in IDS:
            if ident not in PATHS:
                cases[ident] = {'status': 'UNSUPPORTED',
                    'reason': ('No concurrent core receive operation.' if ident.endswith('N01')
                               else 'The 1000-record cap prevents a valid 1024-slot window overflow.')}
                continue
            scenario_sha256, queries = requests(root, ident)
            wire = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n'
                           for row in queries).encode()
            proc = subprocess.run([str(binary)], input=wire, capture_output=True,
                                  timeout=15, check=False)
            require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024 and
                    len(proc.stderr) <= 1024 * 1024,
                    'stateful adapter failed or exceeded bound: ' + language + '/' + ident)
            responses = [load(line) for line in proc.stdout.splitlines()]
            require(len(responses) == len(queries) and
                    all(type(row) is dict and set(row) == {'schema_version',
                        'case_id', 'step_id', 'verdict', 'output', 'effects'} and
                        row['schema_version'] == 2 and row['case_id'] == ident and
                        row['step_id'] == query['step_id'] and
                        row['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED') and
                        type(row['output']) is dict
                        for row, query in zip(responses, queries)),
                    'stateful response identity: ' + language + '/' + ident)
            cases[ident] = {'scenario_sha256': scenario_sha256,
                            'requests': queries, 'responses': responses,
                            **project(root, ident, responses)}
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
            check_vectors(root) == 5, 'stateful report provenance')
    for language in REVISIONS:
        repository, revision = REVISIONS[language]
        subject = report['subjects'][language]
        require(subject['repository'] == repository and
                subject['revision'] == revision and
                len(subject['executable_sha256']) == 64,
                'stateful subject identity: ' + language)
        cases = report['cases'][language]
        require(set(cases) == set(IDS), 'stateful case inventory: ' + language)
        for ident in IDS:
            row = cases[ident]
            if ident not in PATHS:
                require(row['status'] == 'UNSUPPORTED' and row['reason'],
                        'unsupported replay boundary: ' + ident)
                continue
            digest, queries = requests(root, ident)
            require(len(row['responses']) == len(queries) and
                    all(type(response) is dict and set(response) == {
                        'schema_version', 'case_id', 'step_id', 'verdict',
                        'output', 'effects'} and
                        response['schema_version'] == 2 and
                        response['case_id'] == ident and
                        response['step_id'] == query['step_id'] and
                        response['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED') and
                        type(response['output']) is dict
                        for response, query in zip(row['responses'], queries)),
                    'stateful response identity: ' + language + '/' + ident)
            require(row['scenario_sha256'] == digest and
                    same(row['requests'], queries) and
                    same(project(root, ident, row['responses']),
                         {key: row[key] for key in ('status', 'verdicts', 'actual')}),
                    'stateful replay observation: ' + language + '/' + ident)
            require(row['status'] == 'PARTIAL', 'stateful replay mismatch: ' + ident)
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            require(same(row['actual'], fixture['expected']),
                    'stateful replay expectation: ' + language + '/' + ident)
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
            require(args.go and args.rust and args.output, 'both binaries and output required')
            print(capture(ROOT, {'go': args.go.resolve(),
                                'rust': args.rust.resolve()}, args.output)['runner_revision'])
    except (ValueError, KeyError, TypeError, OSError,
            subprocess.SubprocessError) as error:
        print('SESSION-05 stateful evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
