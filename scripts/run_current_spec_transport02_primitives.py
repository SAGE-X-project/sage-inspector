#!/usr/bin/env python3
"""Observe bounded whole-request signature primitives in pinned cores."""

import base64
import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core
from check_current_spec_transport02_vectors import IDS, DOMAIN, request, unsigned


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def inputs(root=ROOT):
    result = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        wire = request(fixture)
        message = DOMAIN + json.dumps(unsigned(wire), sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=False,
                                      allow_nan=False).encode()
        result[ident] = {
            'algorithm': 'ed25519',
            'public_key_hex': fixture['input']['input']['trusted_keys'][wire['kid']],
            'message_hex': message.hex(),
            'signature_hex': base64.urlsafe_b64decode(
                wire['signature'] + '==').hex(),
        }
    return result


def run(programs, repositories, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh output directory outside repository required')
    prepared = inputs(root)
    require(tuple(prepared) == IDS, 'transport request primitive case identity')
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
    observations = {}
    for language, program in programs.items():
        observations[language] = {}
        for ident in IDS:
            observations[language][ident] = invoke_core(
                program, ident, 'signature.verify', prepared[ident])
    require(all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'core primitive executable changed during run')
    report = {
        'schema_version': 1,
        'source_sha256': sha((root / 'vectors/0.10.0/http-boundaries.json').read_bytes()),
        'fixture_sha256': {ident: sha((root / 'vectors/0.10.0/current-spec' /
                              (ident + '.json')).read_bytes()) for ident in IDS},
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'bridge_sha256': sha((root / 'scripts/current_spec_primitive_bridge.py').read_bytes()),
        'runner_revision': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip(),
        'subjects': subjects, 'inputs': prepared, 'observations': observations,
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
    for language, cases in report['observations'].items():
        print(language, {ident: row['verdict'] for ident, row in cases.items()})


if __name__ == '__main__':
    main()
