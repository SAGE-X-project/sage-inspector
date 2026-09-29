"""Run revision-bound runtime fixtures against one explicit local adapter."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import load_bindings, validate_outcome


def run(root, adapter, repository, revision, output, selected=None,
        subject_executable=None,
        runner_revision=None, timeout=10):
    manifest, trace, mapped = catalog(root)
    children = {child['id']: child for child in trace['mandatory_subscenarios']}
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children)
    runtime = {key: value for key, value in bindings.items() if key[1] == 'runtime'}
    if selected is not None:
        runtime = {key: value for key, value in runtime.items() if key[0] == selected}
    require(runtime, 'no runtime fixture is bound for the selected case(s)')
    require(type(repository) is str and repository, 'subject repository')
    require(re.fullmatch('[0-9a-f]{40}', revision) is not None, 'subject revision')
    require(adapter.is_file() and not adapter.is_symlink(), 'adapter executable path')
    if subject_executable is not None:
        require(subject_executable.is_file() and not subject_executable.is_symlink(),
                'subject executable path')
        configured = os.environ.get('SAGE_CORE_ADAPTER')
        if configured is not None:
            require(Path(configured).resolve() == subject_executable.resolve(),
                    'observed core adapter differs from pinned subject executable')
    require(not output.exists() and not output.resolve().is_relative_to(root.resolve()),
            'new output directory outside repository required')
    if runner_revision is None:
        runner_revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip()
    require(re.fullmatch('[0-9a-f]{40}', runner_revision) is not None,
            'runner revision')
    subject = {'repository': repository, 'revision': revision,
               'executable_sha256': sha((subject_executable or adapter).read_bytes())}
    adapter_sha256 = sha(adapter.read_bytes())
    runner_sha256 = sha(Path(__file__).read_bytes())
    output.mkdir(parents=True)
    rows = []
    for (ident, track), (binding, fixture) in sorted(runtime.items()):
        require(re.fullmatch('[A-Za-z0-9-]+', ident) is not None,
                'unsafe case ID for evidence filename')
        request = {'schema_version': 1, 'spec_revision': manifest['spec_revision'],
                   'id': ident, 'track': track, 'input': fixture['input']}
        proc = subprocess.run([str(adapter)],
                              input=json.dumps(request, sort_keys=True,
                                               separators=(',', ':')).encode(),
                              capture_output=True, timeout=timeout, check=False)
        require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024
                and len(proc.stderr) <= 1024 * 1024,
                'adapter failed or exceeded output bound: ' + ident)
        try:
            response = load(proc.stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError('invalid adapter JSON: ' + ident) from error
        require(type(response) is dict and set(response) ==
                {'schema_version', 'id', 'track', 'actual'} and
                response['schema_version'] == 1 and
                (response['id'], response['track']) == (ident, track),
                'adapter response identity: ' + ident)
        validate_outcome(response['actual'])
        evidence = {'schema_version': 1, 'spec_revision': manifest['spec_revision'],
                    'id': ident, 'track': track,
                    'fixture_sha256': binding['fixture_sha256'],
                    'input_sha256': sha(json.dumps(fixture['input'], sort_keys=True,
                                                   separators=(',', ':'),
                                                   allow_nan=False).encode()),
                    'subject': subject, 'actual': response['actual'],
                    'environment': 'bounded-local-adapter'}
        path = ident + '-' + track + '.json'
        raw = (json.dumps(evidence, indent=2) + '\n').encode()
        (output / path).write_bytes(raw)
        rows.append({'id': ident, 'track': track, 'path': path, 'sha256': sha(raw)})
    require(sha((subject_executable or adapter).read_bytes()) == subject['executable_sha256']
            and sha(adapter.read_bytes()) == adapter_sha256,
            'subject or adapter executable changed during run')
    run_manifest = {'schema_version': 1, 'spec_revision': manifest['spec_revision'],
                    'subject': subject, 'runner_revision': runner_revision,
                    'runner_sha256': runner_sha256, 'adapter_sha256': adapter_sha256,
                    'observations': rows}
    (output / 'manifest.json').write_text(json.dumps(run_manifest, indent=2) + '\n')
    return run_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--subject-executable', type=Path,
                        help='Actual implementation binary when --adapter is a bridge')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case')
    args = parser.parse_args()
    try:
        report = run(ROOT, args.adapter.resolve(), args.repository, args.revision,
                     args.output, selected=args.case,
                     subject_executable=(args.subject_executable.resolve()
                                         if args.subject_executable else None))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print('Current spec runtime FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Captured ' + str(len(report['observations'])) +
          ' revision-bound runtime observations; assess them separately.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
