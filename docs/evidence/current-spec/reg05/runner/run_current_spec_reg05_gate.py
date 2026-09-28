#!/usr/bin/env python3
"""Observe fixed Registry freshness scenarios in local pinned core gates."""

import json
from pathlib import Path
import subprocess
import tempfile

from check_current_spec_reg05_vectors import SOURCE, IDS, CONTROLS
from current_spec_catalog import ROOT, load, require, sha


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def run(programs, repositories, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh output directory outside repository')
    suite = load((root / SOURCE).read_bytes())
    rows = suite['cases'] + suite['supplemental']
    require(tuple(row['id'] for row in suite['cases']) == IDS and
            tuple(row['id'] for row in suite['supplemental']) == CONTROLS,
            'bounded Registry scenario inventory')
    subjects = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'pinned Registry gate binary')
        repo = repositories[language]
        require(repo.is_dir() and not repo.is_symlink(),
                'pinned core repository')
        repository, revision = REVISIONS[language]
        actual_revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, timeout=10).strip()
        require(actual_revision == revision and
                not subprocess.check_output(['git', 'diff', 'HEAD', '--'],
                                            cwd=repo, timeout=10),
                'pinned core revision and tracked source')
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(program.read_bytes())}
    require(set(subjects) == {'go', 'rust'}, 'both pinned core gates')
    observations = {}
    with tempfile.TemporaryDirectory(prefix='sage-reg05-gate-') as temporary:
        for language, program in programs.items():
            observations[language] = {}
            for row in rows:
                scenario = row['scenario']
                requests = [{'id': str(index), 'request': step['request']}
                            for index, step in enumerate(scenario['steps'])]
                wire = ''.join(json.dumps(request, separators=(',', ':')) + '\n'
                               for request in requests).encode()
                require(len(wire) < 65536, 'bounded Registry scenario input')
                journal = Path(temporary) / (language + '-' + row['id'])
                process = subprocess.run([str(program), str(journal), 'create'],
                                         input=wire, capture_output=True,
                                         timeout=15, check=False)
                require(process.returncode == 0 and
                        len(process.stdout) < 65536 and
                        len(process.stderr) < 65536 and
                        not process.stderr,
                        'bounded Registry gate process: ' + language + '/' + row['id'])
                actual = [load(line) for line in process.stdout.splitlines()]
                expected = [{'id': str(index), **step['expected']}
                            for index, step in enumerate(scenario['steps'])]
                require(actual == expected,
                        'Registry gate step result: ' + language + '/' + row['id'])
                observations[language][row['id']] = {
                    'source_scenario': row['source_scenario'],
                    'focus_step': row['focus_step'],
                    'input_sha256': sha(wire), 'actual_steps': actual,
                    'focus_actual': actual[row['focus_step']],
                }
    require(all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'stable core gate executable identity')
    report = {
        'schema_version': 1,
        'spec_revision': suite['spec_revision'],
        'scenario_sha256': sha((root / SOURCE).read_bytes()),
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'runner_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
        'scope': 'synthetic trusted source, injected clock, and local journal; no deployed finality proof',
        'subjects': subjects, 'observations': observations,
    }
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'go-repo', 'rust-repo', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    report = run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
                 {'go': args.go_repo.resolve(),
                  'rust': args.rust_repo.resolve()},
                 args.output.resolve())
    for language, rows in report['observations'].items():
        print(language, len(rows), 'bounded Registry scenarios matched')


if __name__ == '__main__':
    main()
