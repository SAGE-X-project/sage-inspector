"""Run protected Go HTTP requests against two authenticated Registry services."""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from observe_reconciled_reg08_admin_mtls import certificates
from observe_reconciled_reg08_public_binding import public_certificate
from observe_reconciled_reg08_service_storage import exchange, start, stop
from observe_registry_operator_service import issue_inspector
from test_completion010 import Actor, ROOT, canonical, digest, independent
from test_http_session010 import audit, body


ORIGIN = 'https://agent.example'
ALICE = 'did:sage:web:agent.example:alice'
BOB = 'did:sage:web:agent.example:bob'
GO_REVISION = '59c7d165c4654873c80f0e0a546e6795819ee55e'
SERVICE_REVISION = 'baf5570578ddc19685ebe2a5bda4a284f45c8e05'
SPEC_REVISION = 'fa006fd917ad365eb554a27f4178301cd66e2379'
RUST_REVISION = 'ffa1234720f7a519b753471cfe315605be7deb1c'


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def public_key(private):
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def record(did, seed, kem):
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    agent = did.rsplit(':', 1)[1]

    def key(name, algorithm, material):
        parts = [b'web:agent.example', agent.encode(), name.encode(), algorithm.encode(), material]
        challenge = b'sage-pop-0.10.0' + b''.join(len(p).to_bytes(2, 'big') + p for p in parts)
        return {'name': name, 'alg': algorithm, 'key': encoded(material),
                'proof': {'signer': did + '#signing-1', 'value': encoded(signer.sign(challenge))},
                'state': 'accepted'}

    keys = []
    if kem:
        private = x25519.X25519PrivateKey.from_private_bytes(bytes([3]) * 32)
        keys.append(key('kem-1', 'x25519', public_key(private)))
    keys.append(key('signing-1', 'ed25519', public_key(signer)))
    return {'id': did, 'controller': 'operator', 'keys': keys, 'services': [],
            'state': 'created', 'version': '1'}


def candidate(value):
    now = int(time.time())
    return json.dumps({'record': value, 'issued': now, 'expires': now + 5},
                      separators=(',', ':')).encode()


def command(did, operation, expected, value):
    return json.dumps({'registry': ORIGIN, 'did': did, 'operation': operation,
                       'expected_version': expected, 'candidate': encoded(candidate(value))},
                      separators=(',', ':')).encode()


def submit(ready, certs, did, operation, expected, value):
    status, _, _ = exchange(ready['admin_addr'], 'admin.example.com', certs['ca_pem'],
                            'POST', '/admin/registry', command(did, operation, expected, value),
                            (certs['client_cert'], certs['client_key']))
    if status != 204:
        raise AssertionError(f'{did} {operation} returned {status}')


def inspect(ready, certs, inspector, did, version):
    status, _, raw = exchange(ready['admin_addr'], 'admin.example.com', certs['ca_pem'],
                              'GET', '/admin/registry/inspection', client=inspector[:2])
    result = json.loads(raw)
    assert status == 200 and result['registry'] == ORIGIN and result['did'] == did
    assert result['version'] == version and len(result['history']) == int(version)
    assert result['tombstoned'] is False
    return result


def build_service(service_root, output):
    binary = output / 'sage-registry-service'
    env = os.environ.copy()
    env['GOCACHE'] = str(output / 'service-go-cache')
    subprocess.run(['go', 'build', '-o', str(binary), './cmd/sage-registry-service'],
                   cwd=service_root, env=env, check=True, timeout=300)
    return binary


def run(service_root, go_root, spec_root, rust_root, sender_adapter, receiver_adapter,
        sender_core, receiver_core, output):
    fixture_path = ROOT / 'vectors/0.10.0/live-web-message010.json'
    fixture = json.loads(fixture_path.read_text())
    assert fixture['schema_version'] == 1 and fixture['kind'] == 'live-web-registry-protected-message'
    assert fixture['cases'] == [{'id': 'before-key-revocation', 'expected': 'ACCEPT'},
                                {'id': 'after-named-key-revocation', 'expected': 'REJECT'}]
    assert fixture['directions'] == ['go-to-go', 'go-to-rust', 'rust-to-go', 'rust-to-rust']
    assert f'{sender_core}-to-{receiver_core}' in fixture['directions']
    assert fixture['conformance'] == 'NOT_ESTABLISHED'
    go_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=go_root, text=True).strip()
    service_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=service_root, text=True).strip()
    spec_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=spec_root, text=True).strip()
    assert (go_revision, service_revision, spec_revision) == (GO_REVISION, SERVICE_REVISION, SPEC_REVISION)
    assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=go_root)
    assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=service_root)
    assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=spec_root)
    rust_revision = None
    if 'rust' in (sender_core, receiver_core):
        assert rust_root is not None
        rust_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                cwd=rust_root, text=True).strip()
        assert rust_revision == RUST_REVISION
        assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=rust_root)
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'kind': fixture['kind'], 'status': 'RUNNING',
              'conformance': 'NOT_ESTABLISHED', 'scope': fixture['scope'],
              'fixture_sha256': digest(fixture_path),
              'inspector_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                            cwd=ROOT, text=True).strip(),
              'go_revision': go_revision, 'service_revision': service_revision,
              'spec_revision': spec_revision, 'rust_revision': rust_revision,
              'sender_core': sender_core, 'receiver_core': receiver_core,
              'adapter_sha256': {'sender': digest(sender_adapter),
                                 'receiver': digest(receiver_adapter)},
              'observations': [], 'raw': 'raw.jsonl'}

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    with (output / 'raw.jsonl').open('w') as raw:
        def log(value):
            raw.write(json.dumps(value, sort_keys=True) + '\n')
            raw.flush()

        try:
            with tempfile.TemporaryDirectory(prefix='sage-live-web-message-') as temp:
                directory = Path(temp)
                certs = certificates(directory)
                inspector = issue_inspector(directory)
                public_cert, public_key_path = public_certificate(directory, 'public', 'agent.example')
                binary = build_service(service_root, directory)
                active = {}
                processes = []
                for did, seed, kem in ((ALICE, 1, False), (BOB, 2, True)):
                    agent = did.rsplit(':', 1)[1]
                    initial = record(did, seed, kem)
                    config = {'public_listen': '127.0.0.1:0', 'admin_listen': '127.0.0.1:0',
                              'public_cert_file': str(public_cert), 'public_key_file': str(public_key_path),
                              'admin_cert_file': str(directory / 'server.pem'),
                              'admin_key_file': str(directory / 'server.key'),
                              'client_ca_file': str(certs['ca_pem']),
                              'client_actors': {certs['client_pin']: 'operator'},
                              'inspector_clients': [inspector[2]],
                              'journal_path': str(directory / (agent + '.journal')),
                              'did': did, 'source': ORIGIN,
                              'admin_host': 'admin.example.com', 'create': True}
                    try:
                        process, ready = start(binary, directory / (agent + '.json'), config)
                        processes.append(process)
                        active[did] = (ready, initial)
                        submit(ready, certs, did, 'create', '', initial)
                        activated = copy.deepcopy(initial)
                        activated.update(state='active', version='2')
                        submit(ready, certs, did, 'activate', '1', activated)
                        inspect(ready, certs, inspector, did, '2')
                    except Exception:
                        for running in reversed(processes):
                            stop(running)
                        raise
                try:
                    config_path = directory / 'live-source.json'
                    config_path.write_text(json.dumps({
                        'origin': ORIGIN, 'admin_host': 'admin.example.com',
                        'root_der': encoded(certs['root_der']),
                        'inspector_cert': str(inspector[0]), 'inspector_key': str(inspector[1]),
                        'agents': {did: {'public': active[did][0]['public_addr'],
                                         'admin': active[did][0]['admin_addr']}
                                   for did in (ALICE, BOB)},
                    }))
                    profile = 'live-web:' + str(config_path)
                    alice = Actor('alice', 'alice', directory / 'alice-session', sender_adapter, log,
                                  profile=profile)
                    bob = Actor('bob', 'bob', directory / 'bob-session', receiver_adapter, log,
                                profile=profile)
                    try:
                        initiation = bytes.fromhex(alice.call('start')['wire_hex'])
                        completion = bytes.fromhex(bob.call('respond', wire_hex=initiation.hex())['wire_hex'])
                        alice.call('complete', wire_hex=completion.hex())
                        independent(initiation, completion)
                        alice.call('http-bind')
                        bob.call('http-bind')
                        first = json.loads(bytes.fromhex(alice.call('http-request-seal',
                            wire_hex=b'allowed'.hex())['wire_hex']))
                        first_base = audit(first, 1)
                        accepted = bob.call('http-request-open', wire_hex=canonical(first).hex())
                        assert bytes.fromhex(accepted['plaintext_hex']) == b'allowed'
                        assert bob.call('record-inspect') == {'state': 'ESTABLISHED', 'reservations': 1}
                        report['observations'].append({'id': 'before-key-revocation',
                                                       'verdict': 'ACCEPT',
                                                       'signature_base_sha256': first_base})
                        save()
                        second = json.loads(bytes.fromhex(alice.call('http-request-seal',
                            wire_hex=b'withheld'.hex())['wire_hex']))
                        second_base = audit(second, 1)
                        one, two = json.loads(body(first)), json.loads(body(second))
                        assert one['id'] != two['id'] and one['nonce'] != two['nonce']

                        ready, initial = active[ALICE]
                        replacement = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
                        material = public_key(replacement)
                        parts = [b'web:agent.example', b'alice', b'signing-2', b'ed25519', material]
                        challenge = b'sage-pop-0.10.0' + b''.join(len(p).to_bytes(2, 'big') + p for p in parts)
                        added = copy.deepcopy(initial)
                        added.update(state='active', version='3')
                        added['keys'].append({'name': 'signing-2', 'alg': 'ed25519',
                            'key': encoded(material), 'state': 'accepted',
                            'proof': {'signer': ALICE + '#signing-2',
                                      'value': encoded(replacement.sign(challenge))}})
                        submit(ready, certs, ALICE, 'add-key', '2', added)
                        revoked = copy.deepcopy(added)
                        revoked['version'] = '4'
                        revoked['keys'][0]['state'] = 'revoked'
                        submit(ready, certs, ALICE, 'revoke-key', '3', revoked)
                        inspect(ready, certs, inspector, ALICE, '4')
                        bob.call('http-request-open', 'REJECT', wire_hex=canonical(second).hex())
                        assert bob.call('record-inspect') == {'state': 'CLOSED', 'reservations': 1}
                        report['observations'].append({'id': 'after-named-key-revocation',
                                                       'verdict': 'REJECT',
                                                       'signature_base_sha256': second_base,
                                                       'replay_reservations': 1})
                        report['status'] = 'PASS'
                    finally:
                        try:
                            alice.close()
                        finally:
                            bob.close()
                finally:
                    for process in reversed(processes):
                        stop(process)
                report['service_executable_sha256'] = digest(binary)
        except Exception as error:
            report['status'], report['reason'] = 'FAIL', str(error)
            raise
        finally:
            raw.flush()
            report['raw_sha256'] = hashlib.sha256((output / 'raw.jsonl').read_bytes()).hexdigest()
            save()
    print('Live Registry reads authorized and then denied protected HTTP requests')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-root', required=True, type=Path)
    parser.add_argument('--go-root', required=True, type=Path)
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--adapter', type=Path)
    parser.add_argument('--sender-adapter', type=Path)
    parser.add_argument('--receiver-adapter', type=Path)
    parser.add_argument('--sender-core', choices=('go', 'rust'), default='go')
    parser.add_argument('--receiver-core', choices=('go', 'rust'), default='go')
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sender = args.sender_adapter or args.adapter
    receiver = args.receiver_adapter or args.adapter
    if sender is None or receiver is None:
        parser.error('both actor executables are required')
    run(args.service_root.resolve(), args.go_root.resolve(), args.spec_root.resolve(),
        args.rust_root.resolve() if args.rust_root else None, sender.resolve(), receiver.resolve(),
        args.sender_core, args.receiver_core, args.output.resolve())
