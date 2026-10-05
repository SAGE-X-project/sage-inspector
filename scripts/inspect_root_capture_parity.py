"""Compare public Go/Rust root-capture constructors using inert independent vectors."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / 'vectors/0.10.0/root-capture-parity.json'
VECTOR_SHA256 = '8c50f78dbb55aea458760dc4cfaf96dcf6dc822eb78f50c70a6707837dd16f49'
GO_ADAPTER = ROOT / 'adapters/root-capture/go/main.go'
RUST_ADAPTER = ROOT / 'adapters/root-capture/rust/main.rs'
NORMATIVE_REVISION = '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9'
GO_REVISION = '8c29b785e36fe8f7d7dc9e55bd9deb036df0088f'
RUST_REVISION = 'c99d373b772a3fb33e166fda3e07ee7ba94414f0'
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reference(case):
    items = [bytes.fromhex(item) for item in case['items_hex']]
    if not UUID.fullmatch(case['request_id']) or len(items) > 1024:
        return 'REJECT'
    total = 0
    for item in items:
        try:
            item.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            return 'REJECT'
        total += len(item)
    if total > 1 << 20:
        return 'REJECT'
    framed = b'sage-original|0.10.0\0' + struct.pack('>I', len(items))
    for item in items:
        framed += struct.pack('>Q', len(item)) + item
    return 'ACCEPT:' + sha(framed)


def vectors():
    raw = VECTORS.read_bytes()
    if sha(raw) != VECTOR_SHA256:
        raise ValueError('root capture vector bytes changed')
    suite = json.loads(raw)
    if set(suite) != {'schema_version', 'protocol_version', 'scope', 'cases'} or \
            suite['schema_version'] != 1 or suite['protocol_version'] != '0.10.0' or \
            len(suite['cases']) != 7:
        raise ValueError('root capture vector contract')
    seen = set()
    for case in suite['cases']:
        if set(case) != {'id', 'request_id', 'items_hex', 'expected'} or \
                case['id'] in seen or case['expected'] != reference(case):
            raise ValueError('root capture expected result')
        seen.add(case['id'])
    return suite, sha(raw)


def check_source(root, revision):
    root = root.resolve(strict=True)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'],
                                    cwd=root, text=True).strip()
    if actual != revision or dirty:
        raise ValueError(f'core source does not match pinned clean revision: {root.name}')
    return root


def build_adapters(temp, go_root, rust_root):
    go_dir = temp / 'go'
    rust_dir = temp / 'rust'
    go_dir.mkdir()
    (rust_dir / 'src').mkdir(parents=True)
    (go_dir / 'go.mod').write_text(
        'module sage-inspector-root-capture\n\ngo 1.26.0\n\n'
        'require github.com/sage-x-project/sage v0.0.0\n'
        f'replace github.com/sage-x-project/sage => {go_root}\n')
    shutil.copyfile(GO_ADAPTER, go_dir / 'main.go')
    (rust_dir / 'Cargo.toml').write_text(
        '[package]\nname = "root_capture_probe"\nversion = "0.0.0"\n'
        'edition = "2021"\nrust-version = "1.88"\n\n[dependencies]\n'
        f'sage_crypto_core = {{ path = {json.dumps(str(rust_root))} }}\n')
    shutil.copyfile(RUST_ADAPTER, rust_dir / 'src/main.rs')
    environment = os.environ.copy()
    environment.update(GOPROXY='off', GOFLAGS='-mod=mod', CARGO_NET_OFFLINE='true',
                       GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    go_binary = temp / 'go-probe'
    subprocess.run(['go', 'build', '-o', str(go_binary), '.'], cwd=go_dir,
                   env=environment, check=True, timeout=300)
    subprocess.run(['cargo', 'build', '--offline', '--quiet'], cwd=rust_dir,
                   env=environment, check=True, timeout=300)
    return go_binary, temp / 'rust-target/debug/root_capture_probe'


def inspect(go_root, rust_root):
    suite, vector_hash = vectors()
    go_root = check_source(go_root, GO_REVISION)
    rust_root = check_source(rust_root, RUST_REVISION)
    with tempfile.TemporaryDirectory(prefix='sage-root-capture-') as directory:
        go_binary, rust_binary = build_adapters(Path(directory), go_root, rust_root)
        results = []
        for case in suite['cases']:
            args = [case['request_id'], *case['items_hex']]
            observed = {}
            for language, binary in [('go', go_binary), ('rust', rust_binary)]:
                result = subprocess.run([str(binary), *args], capture_output=True,
                                        text=True, timeout=10, check=True)
                if result.stderr or result.stdout != case['expected'] + '\n':
                    raise ValueError(f'{language} differs on {case["id"]}')
                observed[language] = result.stdout.strip()
            results.append({'id': case['id'], 'expected': case['expected'], **observed})
    return {
        'schema_version': 1, 'kind': 'root-capture-public-api-parity',
        'protocol_version': '0.10.0', 'normative_source_revision': NORMATIVE_REVISION,
        'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
        'vector_sha256': vector_hash,
        'go_adapter_sha256': sha(GO_ADAPTER.read_bytes()),
        'rust_adapter_sha256': sha(RUST_ADAPTER.read_bytes()),
        'status': 'CAPTURE_CONSTRUCTOR_PARITY', 'protected_client': 'NOT_RUN',
        'deployed_host': 'NOT_RUN', 'cases': results,
    }


def check_report(report):
    suite, vector_hash = vectors()
    if set(report) != {'schema_version', 'kind', 'protocol_version',
                       'normative_source_revision', 'go_revision', 'rust_revision',
                       'vector_sha256', 'go_adapter_sha256', 'rust_adapter_sha256',
                       'status', 'protected_client', 'deployed_host', 'cases'} or \
            report['schema_version'] != 1 or \
            report['kind'] != 'root-capture-public-api-parity' or \
            report['protocol_version'] != '0.10.0' or \
            report['normative_source_revision'] != NORMATIVE_REVISION or \
            report['go_revision'] != GO_REVISION or \
            report['rust_revision'] != RUST_REVISION or \
            report['vector_sha256'] != vector_hash or \
            report['go_adapter_sha256'] != sha(GO_ADAPTER.read_bytes()) or \
            report['rust_adapter_sha256'] != sha(RUST_ADAPTER.read_bytes()) or \
            report['status'] != 'CAPTURE_CONSTRUCTOR_PARITY' or \
            report['protected_client'] != 'NOT_RUN' or report['deployed_host'] != 'NOT_RUN':
        raise ValueError('root capture report scope or provenance')
    expected = [
        {'id': case['id'], 'expected': case['expected'],
         'go': case['expected'], 'rust': case['expected']}
        for case in suite['cases']
    ]
    if report['cases'] != expected:
        raise ValueError('root capture observations differ')
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root):
        parser.error('supply both core roots or neither')
    if args.go_root:
        report = inspect(args.go_root, args.rust_root)
        check_report(report)
        if args.output:
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'cases': len(report['cases']), 'status': report['status'],
                          'deployed_host': report['deployed_host']}))
    else:
        if args.output:
            parser.error('--output requires core roots')
        report = json.loads((ROOT / 'docs/evidence/root-capture-parity.json').read_text())
        print(json.dumps({'cases': check_report(report), 'status': report['status'],
                          'deployed_host': report['deployed_host']}))


if __name__ == '__main__':
    main()
