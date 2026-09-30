"""Observe the pinned REG-08 media subconditions in both core executables."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import VECTOR, check


GO_REVISION = '1dc22e71673bfa40cc63b342a2e66fdfee2f3ee2'
RUST_REVISION = '79fe9bbcd7a417a523d77a267c8420cf4f506746'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-media-Cargo.lock'
RUST_LOCK_SHA256 = 'd99e1e7f037561e6ef5bbd7ae4a0e5090e1d0cb26f6b1148cd832f131c0b5c5a'
VERDICTS = {'MEDIA_ACCEPT', 'RECORD_INVALID'}


def revision(root):
    """Read the checked-out subject identity, including any dirty state."""
    value = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                    text=True, timeout=10).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=root,
                                    text=True, timeout=10).strip()
    require(not dirty, 'subject checkout has local changes: ' + str(root))
    return value


def build(go_root, rust_root, output, lock_source):
    """Compile fresh bounded local adapters from the pinned source checkouts."""
    go_binary = output / 'sage-reg08-media-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-media010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    rust_target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_media010', '--target-dir', str(rust_target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = rust_target / 'debug' / 'examples' / 'registry_media010'
    require(go_binary.is_file() and rust_binary.is_file(), 'adapter binary missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, row):
    """Read one strict bounded verdict from a local subprocess."""
    request = {key: row[key] for key in ('header_lines', 'trailer_lines') if key in row}
    process = subprocess.run([str(binary)], input=json.dumps(request), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'adapter execution failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict'} and
            response['verdict'] in VERDICTS, 'invalid adapter verdict: ' + row['id'])
    return response['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Return observed bounded results without promoting REG-08 parent cases."""
    reference = check(root, spec_root)
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    suite = json.loads((root / VECTOR).read_text())
    with tempfile.TemporaryDirectory(prefix='sage-reg08-media-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        observations = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            observations[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == 13 and item['total'] == 13
                for item in observations.values()), 'core media mismatch')
    return {
        'schema_version': 1,
        'kind': 'reg08-media-core-observation',
        'spec_revision': REVISION,
        'vector_sha256': sha((root / VECTOR).read_bytes()),
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'reference_subconditions': reference['checked_subconditions'],
        'subjects': observations,
        'parent_cases': {'REG-08-P': 'NOT_RUN', 'REG-08-N04': 'NOT_RUN'},
        'web_origin': 'NOT_RUN', 'complete_registry_record': 'NOT_RUN',
        'conformance': 'NOT_ESTABLISHED',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = observe(args.go_root, args.rust_root, args.spec_root)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        parser.exit(1, 'REG-08 core media observation FAIL: ' + str(error) + '\n')
    print('REG-08 media: Go 13/13, Rust 13/13; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
