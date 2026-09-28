#!/usr/bin/env python3
"""Observe bounded outer and inner signature primitives on fixed HTTP wires."""

import base64
import copy
import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, load, require, sha
from current_spec_primitive_bridge import invoke_core
from check_current_spec_transport05_vectors import COMPONENTS, SOURCE, VARIANTS, parse


REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def inputs(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    source = {row['id']: row for row in
              load((root / 'vectors/0.10.0/http-boundaries.json').read_bytes())['cases']}
    public = source['valid-request']['input']['public_key_hex']
    result = {}
    for row in suite['variants']:
        name = row['name']
        headers, body = parse(bytes.fromhex(row['request_hex']))
        components = {'@method': 'POST',
                      '@target-uri': 'https://agent.example/call?x=1',
                      '@authority': headers['host']}
        components.update(headers)
        base = ('\n'.join('"' + key + '": ' + components[key]
                          for key in COMPONENTS) +
                '\n"@signature-params": ' +
                headers['signature-input'].removeprefix('sig1=')).encode()
        cases = {}
        if 'signature' in headers:
            cases['outer'] = {
                'algorithm': 'ed25519', 'public_key_hex': public,
                'message_hex': base.hex(),
                'signature_hex': base64.b64decode(
                    headers['signature'].removeprefix('sig1=:').removesuffix(':'),
                    validate=True).hex(),
            }
        if 'signature' in body:
            unsigned = copy.deepcopy(body)
            signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
            message = b'sage-wire-request|0.10.0\n' + json.dumps(
                unsigned, sort_keys=True, separators=(',', ':'),
                ensure_ascii=False, allow_nan=False).encode()
            cases['inner'] = {
                'algorithm': 'ed25519', 'public_key_hex': public,
                'message_hex': message.hex(), 'signature_hex': signature.hex(),
            }
        result[name] = cases
    require(tuple(result) == VARIANTS and
            sum(len(case) for case in result.values()) == 16,
            'sixteen fixed HTTP signature primitive inputs')
    return result


def run(programs, output, root=ROOT):
    require(not output.exists() and
            not output.resolve().is_relative_to(root.resolve()),
            'fresh evidence directory outside repository')
    prepared = inputs(root)
    subjects = {}
    observations = {}
    for language, program in programs.items():
        require(language in REVISIONS and program.is_file() and
                not program.is_symlink(), 'pinned core adapter executable')
        repository, revision = REVISIONS[language]
        subjects[language] = {'repository': repository, 'revision': revision,
                              'executable_sha256': sha(program.read_bytes())}
        observations[language] = {}
        for name, cases in prepared.items():
            observations[language][name] = {
                side: invoke_core(program, name + '-' + side,
                                  'signature.verify', value)
                for side, value in cases.items()}
    require(set(subjects) == {'go', 'rust'} and
            all(sha(program.read_bytes()) ==
                subjects[language]['executable_sha256']
                for language, program in programs.items()),
            'both core executable identities remained stable')
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
        print(language, {name: list(parts) for name, parts in cases.items()})


if __name__ == '__main__':
    main()
