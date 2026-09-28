#!/usr/bin/env python3
"""Capture bounded legacy DID parser responses for reserved-profile controls."""

import json
from pathlib import Path
import subprocess

from check_current_spec_reg07_vectors import SOURCE, SPEC
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
            'fresh primitive output directory outside repository')
    suite = load((root / SOURCE).read_bytes())
    controls = suite['primitive_controls']
    require(tuple(row['id'] for row in controls) ==
            ('reserved', 'web', 'eip155'), 'fixed parser control inventory')
    subjects = {}
    observations = {}
    for language, binary in programs.items():
        require(language in REVISIONS and binary.is_file() and
                not binary.is_symlink(), 'pinned core primitive executable')
        repository, revision = REVISIONS[language]
        repo = repositories[language]
        require(repo.is_dir() and not repo.is_symlink() and
                subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                        cwd=repo, text=True, timeout=10).strip() == revision and
                not subprocess.check_output(['git', 'diff', 'HEAD', '--'],
                                            cwd=repo, timeout=10),
                'pinned core source revision')
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(binary.read_bytes())}
        observations[language] = {}
        for row in controls:
            request = {'schema_version': 1, 'protocol_version': '0.10.0',
                       'profile': 'primitive-foundation',
                       'case_id': 'REG-07-' + row['id'],
                       'operation': 'sage.did.validate',
                       'input': {'did': row['did']}}
            raw = json.dumps(request, sort_keys=True,
                             separators=(',', ':')).encode()
            result = subprocess.run([str(binary)], input=raw,
                                    capture_output=True, timeout=10,
                                    check=False)
            require(result.returncode == 0 and len(result.stdout) < 4096
                    and not result.stderr,
                    'bounded primitive response: ' + language + '/' + row['id'])
            response = load(result.stdout)
            require(response['schema_version'] == 1 and
                    response['case_id'] == request['case_id'] and
                    response['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED')
                    and type(response['output']) is dict,
                    'typed primitive response: ' + language + '/' + row['id'])
            observations[language][row['id']] = {
                'input_sha256': sha(raw), 'actual': response}
        require(sha(binary.read_bytes()) ==
                subjects[language]['executable_sha256'],
                'stable primitive executable')
    require(set(subjects) == set(REVISIONS), 'both pinned core subjects')
    report = {
        'schema_version': 1, 'spec_revision': SPEC,
        'scenario_sha256': sha((root / SOURCE).read_bytes()),
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'runner_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
        'scope': 'legacy DID syntax primitive only; no Registry resolver or profile admission',
        'subjects': subjects, 'observations': observations,
    }
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'go-repo', 'rust-repo', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    report = run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
                 {'go': args.go_repo.resolve(),
                  'rust': args.rust_repo.resolve()},
                 args.output.resolve())
    for language, rows in report['observations'].items():
        print(language, len(rows), 'legacy parser observations')


if __name__ == '__main__':
    main()
