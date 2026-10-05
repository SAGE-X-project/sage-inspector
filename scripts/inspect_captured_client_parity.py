"""Exercise signed, captured Client opens and durable restarts through public Go/Rust APIs."""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from inspect_root_capture_parity import (GO_REVISION, NORMATIVE_REVISION, ROOT,
                                         RUST_REVISION, check_source, reference, sha, vectors)

GO_SOURCE = ROOT / 'adapters/captured-client/go'
RUST_SOURCE = ROOT / 'adapters/captured-client/rust/main.rs'
FIXTURE = ROOT / 'vectors/0.10.0/guard-client.json'
HEADER = b'sage-guard-client|0.10.0\n'
OUTER = '00000000-0000-4000-8000-000000000001'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()


def signed_fixture():
    fixture_raw = FIXTURE.read_bytes()
    fixture = json.loads(fixture_raw)
    suite, vector_hash = vectors()
    original = suite['cases'][0]
    if original['id'] != 'single-utf8' or not original['expected'].startswith('ACCEPT:'):
        raise ValueError('independent capture vector')
    digest = reference(original).removeprefix('ACCEPT:')
    if original['expected'] != 'ACCEPT:' + digest:
        raise ValueError('original byte commitment')
    config = copy.deepcopy(fixture['input'])
    envelope = json.loads(bytes.fromhex(config['envelope_hex']))
    if envelope['intent']['request_id'] != original['request_id']:
        raise ValueError('signed intent request identity')
    config['original_digest'] = digest
    envelope['intent']['original_digest'] = digest
    seed = hashlib.sha256(b'public Guard fixture issuer').digest()
    signer = Ed25519PrivateKey.from_private_bytes(seed)
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    if public != config['public_key_hex']:
        raise ValueError('fixture signer identity')
    message = b'sage-execution-intent|0.10.0\0' + canonical(envelope['intent'])
    envelope['proof'] = base64.urlsafe_b64encode(signer.sign(message)).rstrip(b'=').decode()
    raw = canonical(envelope)
    signer.public_key().verify(base64.urlsafe_b64decode(envelope['proof'] + '=='), message)
    config['envelope_hex'] = raw.hex()
    return config, fixture['public_key_hex'], original, sha(fixture_raw), vector_hash


def build(temp, go_root, rust_root):
    go_dir, rust_dir = temp / 'go', temp / 'rust'
    go_dir.mkdir()
    (rust_dir / 'src').mkdir(parents=True)
    for name in ('main.go', 'fixtures.go'):
        shutil.copyfile(GO_SOURCE / (name + '.txt'), go_dir / name)
    (go_dir / 'go.mod').write_text(
        'module sage-inspector-captured-client\n\ngo 1.26.0\n\n'
        'require github.com/sage-x-project/sage v0.0.0\n'
        f'replace github.com/sage-x-project/sage => {go_root}\n')
    shutil.copyfile(RUST_SOURCE, rust_dir / 'src/main.rs')
    (rust_dir / 'Cargo.toml').write_text(
        '[package]\nname = "captured_client_probe"\nversion = "0.0.0"\n'
        'edition = "2021"\nrust-version = "1.88"\n\n[dependencies]\n'
        f'sage_crypto_core = {{ path = {json.dumps(str(rust_root))} }}\n'
        'serde = { version = "1.0", features = ["derive"] }\n'
        'serde_json = "1.0"\nhex = "0.4"\n')
    environment = os.environ.copy()
    environment.update(GOPROXY='off', GOFLAGS='-mod=mod', CARGO_NET_OFFLINE='true',
                       GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    go_binary = temp / 'go-probe'
    subprocess.run(['go', 'build', '-o', str(go_binary), '.'], cwd=go_dir,
                   env=environment, check=True, timeout=300)
    subprocess.run(['cargo', 'build', '--offline', '--quiet'], cwd=rust_dir,
                   env=environment, check=True, timeout=300)
    return {'go': go_binary, 'rust': temp / 'rust-target/debug/captured_client_probe'}


def observe(binary, journal, mode, commands, allowed):
    wire = b''.join(canonical(command) + b'\n' for command in commands)
    process = subprocess.run([str(binary), str(journal), mode], input=wire,
                             capture_output=True, timeout=10)
    if process.returncode != (0 if allowed else 2) or process.stderr or \
            (not allowed and process.stdout):
        raise ValueError('captured Client process verdict')
    return [json.loads(line) for line in process.stdout.splitlines()]


def check_journal(path, events):
    raw = path.read_bytes()
    if not raw.startswith(HEADER) or not raw.endswith(b'\n') or \
            [json.loads(line) for line in raw[len(HEADER):].splitlines()] != events:
        raise ValueError('captured Client journal events')
    return raw


def inspect(go_root, rust_root):
    go_root = check_source(go_root, GO_REVISION)
    rust_root = check_source(rust_root, RUST_REVISION)
    config, result_public, original, fixture_hash, vector_hash = signed_fixture()
    request_id = original['request_id']
    command = {'action': 'open_captured', 'input': config,
               'public_key_hex': result_public, 'utc': 1700000000000, 'mono': 0,
               'capture_items_hex': original['items_hex'],
               'capture_request_id': request_id}
    intent_hex = config['envelope_hex']
    open_event = {'kind': 'open', 'id': '', 'at': 0, 'intent_hex': intent_hex,
                  'result_hex': ''}
    send_event = {'kind': 'send', 'id': OUTER, 'at': 1700000000000,
                  'intent_hex': '', 'result_hex': ''}
    with tempfile.TemporaryDirectory(prefix='sage-captured-client-') as directory:
        root = Path(directory)
        binaries = build(root, go_root, rust_root)
        cases = []
        journals = {}
        for language, binary in binaries.items():
            for label, items, identity in (
                    ('changed-original', ['6368616e67656420726f6f7420696e707574'], request_id),
                    ('changed-request-id', original['items_hex'],
                     '00000000-0000-4000-8000-000000000099')):
                candidate = dict(command, capture_items_hex=items,
                                 capture_request_id=identity)
                path = root / f'{language}-{label}'
                observe(binary, path, 'create', [candidate], False)
                if path.exists() or path.with_name(path.name + '.lock').exists():
                    raise ValueError('rejected capture created durable state')
                cases.append({'id': f'{language}-{label}', 'status': 'PASS',
                              'journal': 'ABSENT', 'handoffs': 0})
            path = root / f'{language}-journal'
            rows = observe(binary, path, 'create',
                           [command, {'action': 'begin', 'id': OUTER},
                            {'action': 'close'}], True)
            if len(rows) != 3 or rows[0]['ok'] is not True or \
                    rows[1]['ok'] is not True or rows[1]['id'] != OUTER or \
                    rows[1]['intent_hex'] != intent_hex or \
                    rows[1]['handoffs'] != 1 or rows[2]['ok'] is not True:
                raise ValueError('signed captured Client handoff')
            raw = check_journal(path, [open_event, send_event])
            journals[language] = path
            cases.append({'id': f'{language}-create-send', 'status': 'PASS',
                          'journal_sha256': sha(raw), 'handoffs': 1})
            changed = dict(command, capture_items_hex=['6368616e67656420726f6f7420696e707574'])
            observe(binary, path, 'reopen', [changed], False)
            if path.read_bytes() != raw:
                raise ValueError('rejected reopen modified journal')
            cases.append({'id': f'{language}-reopen-changed', 'status': 'PASS',
                          'journal_sha256': sha(raw), 'handoffs': 0})
            later = dict(command, utc=1700000001000)
            rows = observe(binary, path, 'reopen',
                           [later, {'action': 'begin', 'id': OUTER},
                            {'action': 'close'}], True)
            if len(rows) != 3 or rows[0]['ok'] is not True or \
                    rows[1]['ok'] is not False or rows[1]['handoffs'] != 0 or \
                    rows[2]['ok'] is not True or path.read_bytes() != raw:
                raise ValueError('captured Client restart duplicated handoff')
            cases.append({'id': f'{language}-reopen-same', 'status': 'PASS',
                          'journal_sha256': sha(raw), 'handoffs': 0})
        for writer, reader in (('go', 'rust'), ('rust', 'go')):
            path = journals[writer]
            before = path.read_bytes()
            later = dict(command, utc=1700000001000)
            rows = observe(binaries[reader], path, 'reopen',
                           [later, {'action': 'begin', 'id': OUTER},
                            {'action': 'close'}], True)
            if len(rows) != 3 or rows[0]['ok'] is not True or \
                    rows[1]['ok'] is not False or rows[1]['handoffs'] != 0 or \
                    rows[2]['ok'] is not True or path.read_bytes() != before:
                raise ValueError('cross-language captured Client restart')
            cases.append({'id': f'{writer}-to-{reader}-reopen', 'status': 'PASS',
                          'journal_sha256': sha(before), 'handoffs': 0})
    if len({case['journal_sha256'] for case in cases if 'journal_sha256' in case}) != 1:
        raise ValueError('Go and Rust captured Client journal parity')
    return {'schema_version': 1, 'kind': 'captured-client-public-api-parity',
            'protocol_version': '0.10.0', 'normative_source_revision': NORMATIVE_REVISION,
            'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
            'fixture_sha256': fixture_hash, 'vector_sha256': vector_hash,
            'go_adapter_sha256': sha((GO_SOURCE / 'main.go.txt').read_bytes() +
                                     (GO_SOURCE / 'fixtures.go.txt').read_bytes()),
            'rust_adapter_sha256': sha(RUST_SOURCE.read_bytes()),
            'status': 'CAPTURED_CLIENT_API_PARITY', 'deployed_host': 'NOT_RUN',
            'full_protocol_conformance': 'NOT_ESTABLISHED', 'cases': cases}


def check_report(report):
    _, _, _, fixture_hash, vector_hash = signed_fixture()
    expected = {'schema_version': 1, 'kind': 'captured-client-public-api-parity',
                'protocol_version': '0.10.0',
                'normative_source_revision': NORMATIVE_REVISION,
                'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
                'fixture_sha256': fixture_hash, 'vector_sha256': vector_hash,
                'go_adapter_sha256': sha((GO_SOURCE / 'main.go.txt').read_bytes() +
                                         (GO_SOURCE / 'fixtures.go.txt').read_bytes()),
                'rust_adapter_sha256': sha(RUST_SOURCE.read_bytes()),
                'status': 'CAPTURED_CLIENT_API_PARITY', 'deployed_host': 'NOT_RUN',
                'full_protocol_conformance': 'NOT_ESTABLISHED'}
    if set(report) != set(expected) | {'cases'} or \
            any(report[key] != value for key, value in expected.items()):
        raise ValueError('captured Client report scope or provenance')
    config, _, _, _, _ = signed_fixture()
    open_event = {'kind': 'open', 'id': '', 'at': 0,
                  'intent_hex': config['envelope_hex'], 'result_hex': ''}
    send_event = {'kind': 'send', 'id': OUTER, 'at': 1700000000000,
                  'intent_hex': '', 'result_hex': ''}
    journal_line = lambda event: json.dumps(event, separators=(',', ':')).encode() + b'\n'
    journal_hash = sha(HEADER + journal_line(open_event) + journal_line(send_event))
    expected_cases = []
    for lang in ('go', 'rust'):
        for label in ('changed-original', 'changed-request-id'):
            expected_cases.append({'id': f'{lang}-{label}', 'status': 'PASS',
                                   'journal': 'ABSENT', 'handoffs': 0})
        for label, handoffs in (('create-send', 1), ('reopen-changed', 0),
                                ('reopen-same', 0)):
            expected_cases.append({'id': f'{lang}-{label}', 'status': 'PASS',
                                   'journal_sha256': journal_hash,
                                   'handoffs': handoffs})
    for writer, reader in (('go', 'rust'), ('rust', 'go')):
        expected_cases.append({'id': f'{writer}-to-{reader}-reopen',
                               'status': 'PASS', 'journal_sha256': journal_hash,
                               'handoffs': 0})
    if report['cases'] != expected_cases:
        raise ValueError('captured Client case verdicts or journal bytes')
    return len(expected_cases)


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
    else:
        if args.output:
            parser.error('--output requires core roots')
        report = json.loads((ROOT / 'docs/evidence/captured-client-parity.json').read_text())
        check_report(report)
    print(json.dumps({'cases': len(report['cases']), 'status': report['status'],
                      'deployed_host': report['deployed_host']}))


if __name__ == '__main__':
    main()
