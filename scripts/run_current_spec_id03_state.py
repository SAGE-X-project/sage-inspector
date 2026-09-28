#!/usr/bin/env python3
"""Run bounded named-key state prerequisites against pinned local core gates."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require, sha


SCENARIOS = ('kem-required', 'exact-signing-url', 'revoked-signing',
             'expiry-equality', 'changed-algorithm')
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def run(programs, repositories, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh output directory outside repository required')
    source_path = root / 'vectors/0.10.0/registry010.json'
    source = load(source_path.read_bytes())
    cases = {row['id']: row for row in source['cases']}
    require(all(ident in cases for ident in SCENARIOS), 'named-key source cases')
    subject = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'local core gate executable')
        repository, revision = REVISIONS[language]
        repo = repositories[language]
        require(repo.is_dir() and not repo.is_symlink(), 'core source checkout')
        actual_revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, timeout=10).strip()
        require(actual_revision == revision and
                not subprocess.check_output(['git', 'diff', 'HEAD', '--'],
                                            cwd=repo, timeout=10),
                'pinned core source revision')
        subject[language] = {'repository': repository, 'revision': revision,
                             'executable_sha256': sha(program.read_bytes())}
    require(set(subject) == {'go', 'rust'}, 'both core gate executables')
    output.mkdir(parents=True)
    report = {'schema_version': 1, 'source_sha256': sha(source_path.read_bytes()),
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'runner_revision': subprocess.check_output(
                  ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
              'subjects': subject, 'scenarios': []}
    with tempfile.TemporaryDirectory() as temporary:
        for language, program in programs.items():
            for ident in SCENARIOS:
                case = cases[ident]
                requests = [step['request'] for step in case['steps']]
                envelopes = [{'id': str(index), 'request': request}
                             for index, request in enumerate(requests)]
                raw = ''.join(json.dumps(row, separators=(',', ':')) + '\n'
                              for row in envelopes).encode()
                journal = Path(temporary) / (language + '-' + ident)
                proc = subprocess.run([str(program), str(journal), 'create'],
                                      input=raw, capture_output=True, timeout=15,
                                      check=False)
                require(proc.returncode == 0 and len(proc.stdout) < 65536 and
                        len(proc.stderr) < 65536, 'core gate process: ' + ident)
                actual = [load(line) for line in proc.stdout.splitlines()]
                expected = [{'id': str(index), **step['expected']}
                            for index, step in enumerate(case['steps'])]
                require(actual == expected,
                        'core gate named-key mismatch: ' + language + '/' + ident)
                report['scenarios'].append({
                    'language': language, 'id': ident,
                    'request_sha256': hashlib.sha256(raw).hexdigest(),
                    'actual': actual, 'stderr': proc.stderr.decode()})
    require(all(sha(program.read_bytes()) ==
                subject[language]['executable_sha256']
                for language, program in programs.items()),
            'core gate executable changed during run')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--go-repo', type=Path, required=True)
    parser.add_argument('--rust-repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
                 {'go': args.go_repo.resolve(),
                  'rust': args.rust_repo.resolve()},
                 args.output.resolve())
    print('Observed', len(report['scenarios']),
          'bounded named-key state scenarios; full signature binding unverified.')


if __name__ == '__main__':
    main()
