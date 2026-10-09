"""Observe frozen design-baseline fixture contracts through 0.10.0 entry points.

Each selected runtime `prior-independent-fixture` contract replays its source
fixture through an explicit bridge whose core adapter runs with the
`primitive-foundation-010` profile, so routed operations reach 0.10.0 core
APIs and legacy-only operations report UNSUPPORTED. Observations use the
design-baseline schema; `design_baseline_evidence.py` assesses them. These
contracts are partial, so a matching outcome is PARTIAL, never PASS.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import validate_outcome
from design_baseline_catalog import PROFILES, SPEC_REVISION, verify as verify_catalog

CORE_PROFILE = 'primitive-foundation-010'
OBSERVER = 'SAGE-X-project/sage-inspector'
# Fixtures whose input is not a primitive operation; other bridges observe
# them, and they stay NOT_RUN here.
NON_PRIMITIVE = ('sage.spec.host_case', 'sage.evidence.review')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode()


def select(contracts, selected, fixture_revision):
    rows = [row for row in contracts if row['contract_kind'] ==
            'prior-independent-fixture' and row['track'] == 'runtime' and
            row['source_fixture_spec_revision'] == fixture_revision and
            row['source_operation'] not in NON_PRIMITIVE]
    if selected is not None:
        requested = set(selected)
        require(requested and all(type(ident) is str and ident for ident in requested),
                'invalid case selection')
        rows = [row for row in rows if row['id'] in requested]
        require({row['id'] for row in rows} == requested,
                'no runtime fixture contract for one or more selected cases')
    require(rows, 'no runtime fixture contract selected')
    return sorted(rows, key=lambda row: row['id'])


def observe(root, adapter, row, timeout):
    raw = (root / row['source_fixture']).read_bytes()
    require(sha(raw) == row['source_fixture_sha256'], 'source fixture drift: ' + row['id'])
    fixture = load(raw)
    require(sha(canonical(fixture['input'])) == row['input_sha256'],
            'fixture input drift: ' + row['id'])
    request = {'schema_version': 1, 'spec_revision': row['source_fixture_spec_revision'],
               'id': row['id'], 'track': 'runtime', 'input': fixture['input']}
    env = dict(os.environ, SAGE_CORE_PROFILE=CORE_PROFILE)
    proc = subprocess.run([str(adapter)], input=canonical(request), env=env,
                          capture_output=True, timeout=timeout, check=False)
    require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024 and
            len(proc.stderr) <= 1024 * 1024,
            'adapter failed or exceeded output bound: ' + row['id'])
    try:
        response = load(proc.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid adapter JSON: ' + row['id']) from error
    require(type(response) is dict and set(response) ==
            {'schema_version', 'id', 'track', 'actual'} and
            response['schema_version'] == 1 and
            (response['id'], response['track']) == (row['id'], 'runtime'),
            'adapter response identity: ' + row['id'])
    validate_outcome(response['actual'])
    return response['actual']


def facts(row, actual, subject, observer):
    if actual.get('verdict') == 'UNSUPPORTED':
        return {}
    return {'subject_revision': subject['revision'],
            'executable_sha256': subject['executable_sha256'],
            'input_sha256': row['input_sha256'],
            'actual_verdict': actual['verdict'],
            'actual_output': actual['output'],
            'effect_counts': actual['effects'],
            'independent_observer': observer}


def run(root, adapter, repository, revision, subject_executable, output,
        selected=None, runner_revision=None, fixture_revision=None, timeout=10):
    _, _, source = verify_catalog(root)
    if fixture_revision is None:
        fixture_revision = catalog(root)[0]['spec_revision']
    rows = select(source['contracts'], selected, fixture_revision)
    require(type(repository) is str and repository and repository != OBSERVER,
            'subject repository')
    require(re.fullmatch('[0-9a-f]{40}', revision) is not None, 'subject revision')
    require(adapter.is_file() and not adapter.is_symlink(), 'adapter executable path')
    require(subject_executable.is_file() and not subject_executable.is_symlink(),
            'subject executable path')
    configured = os.environ.get('SAGE_CORE_ADAPTER')
    require(configured and Path(configured).resolve() == subject_executable.resolve(),
            'observed subject adapter differs from pinned executable')
    require(not output.exists() and not output.resolve().is_relative_to(root.resolve()),
            'new output directory outside repository required')
    if runner_revision is None:
        runner_revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip()
    require(re.fullmatch('[0-9a-f]{40}', runner_revision) is not None, 'runner revision')
    subject = {'repository': repository, 'revision': revision,
               'executable_sha256': sha(subject_executable.read_bytes())}
    output.mkdir(parents=True)
    (output / 'runner').mkdir()
    artifacts = []
    for source_path in (Path(__file__), adapter):
        target = output / 'runner' / source_path.name
        shutil.copyfile(source_path, target)
        artifacts.append({'path': 'runner/' + source_path.name,
                          'sha256': sha(target.read_bytes())})
    runner_sha256, adapter_sha256 = (item['sha256'] for item in artifacts)
    observer = {'repository': OBSERVER, 'revision': runner_revision,
                'artifact_sha256': runner_sha256}
    observations = []
    for row in rows:
        require(re.fullmatch('[A-Za-z0-9-]+', row['id']) is not None,
                'unsafe case ID for evidence filename')
        actual = observe(root, adapter, row, timeout)
        evidence = {'schema_version': 1, 'spec_revision': SPEC_REVISION,
                    'id': row['id'], 'track': 'runtime',
                    'source_fixture_sha256': row['source_fixture_sha256'],
                    'subject': subject, 'actual': actual,
                    'facts': facts(row, actual, subject, observer),
                    'environment': 'local-process'}
        path = row['id'] + '-runtime.json'
        raw = (json.dumps(evidence, indent=2) + '\n').encode()
        (output / path).write_bytes(raw)
        observations.append({'id': row['id'], 'track': 'runtime', 'path': path,
                             'sha256': sha(raw)})
    require(sha(subject_executable.read_bytes()) == subject['executable_sha256'] and
            sha(adapter.read_bytes()) == adapter_sha256,
            'subject or adapter executable changed during run')
    manifest = {'schema_version': 1, 'protocol_version': '0.10.0',
                'spec_revision': SPEC_REVISION, 'subject': subject,
                'runner_revision': runner_revision, 'runner_sha256': runner_sha256,
                'adapter_sha256': adapter_sha256, 'observations': observations,
                'artifacts': artifacts, 'profiles': list(PROFILES)}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True,
                        help='Bridge that forwards SAGE_CORE_PROFILE to SAGE_CORE_ADAPTER')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--subject-executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append',
                        help='Run one named case; repeat to select several cases')
    args = parser.parse_args()
    try:
        report = run(ROOT, args.adapter.resolve(), args.repository, args.revision,
                     args.subject_executable.resolve(), args.output, selected=args.case)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print('Design baseline fixture run FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Captured ' + str(len(report['observations'])) +
          ' design-baseline runtime observations; assess them separately.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
