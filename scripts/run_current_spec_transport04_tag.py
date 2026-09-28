#!/usr/bin/env python3
"""Open one fixed malformed AEAD record in bounded local core processes."""

import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def input_case(root=ROOT):
    source = load((root / 'vectors/0.10.0/session-records.json').read_bytes())
    row = next(row for row in source['cases'] if row['id'] == 'tag')
    require(row['operation'] == 'sage.session.record.open' and
            row['expected'] == {'verdict': 'REJECT', 'output': {}},
            'independent failed-tag source')
    return {key: value for key, value in row['input'].items() if key != 'sid'}


def run(programs, repositories, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh output directory outside repository required')
    prepared = input_case(root)
    subjects = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'core primitive executable')
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
    require(set(subjects) == {'go', 'rust'}, 'both core primitive executables')
    observations = {language: invoke_core(
        program, 'TRANSPORT-04-N03-tag', 'sage.session.record010.open', prepared)
        for language, program in programs.items()}
    require(all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'core primitive executable changed during run')
    report = {
        'schema_version': 1,
        'source_sha256': sha((root / 'vectors/0.10.0/session-records.json').read_bytes()),
        'scenario_sha256': sha((root / 'vectors/0.10.0/transport04-scenarios.json').read_bytes()),
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'bridge_sha256': sha((root / 'scripts/current_spec_primitive_bridge.py').read_bytes()),
        'runner_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
        'subjects': subjects, 'input': prepared, 'observations': observations,
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
                  'rust': args.rust_repo.resolve()}, args.output.resolve())
    for language, row in report['observations'].items():
        print(language, row['verdict'])


if __name__ == '__main__':
    main()
