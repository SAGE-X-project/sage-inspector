#!/usr/bin/env python3
"""Probe pinned local registry gates for mutation support without changing state."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require, sha


DID = ('did:sage:eip155:1:0xabababababababababababababababababababab:'
       'alice')
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
    source_path = root / 'vectors/0.10.0/registry-scenarios/registry-mutations.json'
    source = load(source_path.read_bytes())
    require(source['steps'][1]['input']['action'] == 'mutate' and
            source['steps'][5]['expected']['verdict'] == 'ACCEPT' and
            source['steps'][5]['effects']['mutations'] == 1,
            'audited registry mutation model')
    subjects = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'local core gate executable')
        repo = repositories[language]
        require(repo.is_dir() and not repo.is_symlink(), 'core source checkout')
        repository, revision = REVISIONS[language]
        actual_revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, timeout=10).strip()
        require(actual_revision == revision and
                not subprocess.check_output(['git', 'diff', 'HEAD', '--'],
                                            cwd=repo, timeout=10),
                'pinned core source revision')
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(program.read_bytes())}
    require(set(subjects) == {'go', 'rust'}, 'both core gate executables')
    requests = [
        {'id': 'before', 'request': {'action': 'inspect', 'did': DID}},
        {'id': 'mutation', 'request': {'action': 'mutate'}},
        {'id': 'after', 'request': {'action': 'inspect', 'did': DID}},
    ]
    expected = [
        {'id': 'before', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
        {'id': 'mutation', 'verdict': 'UNSUPPORTED', 'output': {}},
        {'id': 'after', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
    ]
    raw = ''.join(json.dumps(row, separators=(',', ':')) + '\n'
                  for row in requests).encode()
    observations = {}
    with tempfile.TemporaryDirectory() as temporary:
        for language, program in programs.items():
            journal = Path(temporary) / (language + '-journal')
            proc = subprocess.run([str(program), str(journal), 'create'],
                                  input=raw, capture_output=True, timeout=15,
                                  check=False)
            require(proc.returncode == 0 and len(proc.stdout) < 65536 and
                    len(proc.stderr) < 65536,
                    'registry mutation capability process: ' + language)
            actual = [load(line) for line in proc.stdout.splitlines()]
            require(actual == expected,
                    'registry mutation capability result: ' + language)
            observations[language] = {'actual': actual,
                                      'stderr': proc.stderr.decode()}
    require(all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'core gate executable changed during run')
    report = {'schema_version': 1,
              'source_sha256': sha(source_path.read_bytes()),
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'runner_revision': subprocess.check_output(
                  ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
              'subjects': subjects, 'requests': requests,
              'observations': observations}
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'go-repo', 'rust-repo', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
        {'go': args.go_repo.resolve(), 'rust': args.rust_repo.resolve()},
        args.output.resolve())
    print('Both pinned registry gates report mutation UNSUPPORTED without journal change.')


if __name__ == '__main__':
    main()
