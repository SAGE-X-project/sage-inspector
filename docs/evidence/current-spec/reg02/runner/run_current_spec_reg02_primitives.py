#!/usr/bin/env python3
"""Observe bounded Registry proof signatures without claiming key selection."""

import json
from pathlib import Path
import subprocess

from check_current_spec_reg01_vectors import decoded, proof_input
from check_current_spec_reg02_vectors import SOURCE
from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}
NAMES = ('selected-proof', 'later-proof', 'unproven-selected-proof',
         'revoked-signer-proof', 'replacement-proof')


def inputs(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    rows = {row['id']: row for row in suite['cases']}
    first = rows['REG-02-P']['input']['record']
    unproven = rows['REG-02-N01']['input']['record']
    revoked = rows['REG-02-N02']['input']['record']
    replaced = rows['REG-02-N03']['input']['candidate_record']
    chosen = {
        'selected-proof': (first, first['keys'][0]),
        'later-proof': (first, first['keys'][1]),
        'unproven-selected-proof': (unproven, unproven['keys'][0]),
        'revoked-signer-proof': (revoked, next(
            key for key in revoked['keys'] if key['name'] == 'signing-1')),
        'replacement-proof': (replaced, replaced['keys'][0]),
    }
    result = {}
    for name, (record, key) in chosen.items():
        signer_name = key['proof']['signer'].split('#', 1)[1]
        signer = next(k for k in record['keys'] if k['name'] == signer_name)
        result[name] = {
            'algorithm': 'ed25519',
            'public_key_hex': decoded(signer['key']).hex(),
            'message_hex': proof_input(record, key).hex(),
            'signature_hex': decoded(key['proof']['value']).hex(),
        }
    require(tuple(result) == NAMES, 'five bounded Registry proof inputs')
    return result


def run(programs, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh output outside repository')
    prepared = inputs(root)
    subjects = {}
    observations = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'bounded core adapter executable')
        repository, revision = REVISIONS[language]
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(program.read_bytes())}
        observations[language] = {
            name: invoke_core(program, 'REG-02-' + name,
                              'signature.verify', fields)
            for name, fields in prepared.items()}
    require(set(subjects) == {'go', 'rust'} and
            all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'stable core executable identities')
    report = {
        'schema_version': 1,
        'spec_revision': load((root / SOURCE).read_bytes())['spec_revision'],
        'scenario_sha256': sha((root / SOURCE).read_bytes()),
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
    for name in ('go', 'rust', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    report = run({'go': args.go.resolve(), 'rust': args.rust.resolve()},
                 args.output.resolve())
    for language, cases in report['observations'].items():
        print(language, {name: row['verdict'] for name, row in cases.items()})


if __name__ == '__main__':
    main()
