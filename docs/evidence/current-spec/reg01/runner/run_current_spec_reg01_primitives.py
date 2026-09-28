#!/usr/bin/env python3
"""Observe fixed key-proof signatures without claiming record validation."""

import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core
from check_current_spec_reg01_vectors import SOURCE, decoded, proof_input


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}
NAMES = ('valid-kem', 'duplicate-name-extra', 'limit-129-extra',
         'casefolded-alg', 'unknown-alg')


def inputs(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    rows = {row['id']: row for row in suite['cases']}
    extras = {row['name']: row for row in suite['supplemental']}
    record = lambda row: load(bytes.fromhex(row['record_hex']))
    valid = record(rows['REG-01-P'])
    duplicate = record(rows['REG-01-N01'])
    over = record(rows['REG-01-N04'])
    casefolded = record(extras['casefolded-kem-alg'])
    unknown = record(extras['unknown-kem-alg'])
    selected = {
        'valid-kem': (valid, valid['keys'][0]),
        'duplicate-name-extra': (duplicate, next(key for key in
            duplicate['keys'] if key['name'] == 'kem-1' and
            key['key'] != valid['keys'][0]['key'])),
        'limit-129-extra': (over, next(key for key in over['keys']
                                       if key['name'] == 'kem-126')),
        'casefolded-alg': (casefolded, casefolded['keys'][0]),
        'unknown-alg': (unknown, unknown['keys'][0]),
    }
    signer = next(key for key in valid['keys'] if key['name'] == 'signing-1')
    result = {}
    for name, (owner, key) in selected.items():
        result[name] = {
            'algorithm': 'ed25519',
            'public_key_hex': decoded(signer['key']).hex(),
            'message_hex': proof_input(owner, key).hex(),
            'signature_hex': decoded(key['proof']['value']).hex(),
        }
    require(tuple(result) == NAMES, 'five isolated registry proof signatures')
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
            name: invoke_core(program, 'REG-01-' + name,
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
