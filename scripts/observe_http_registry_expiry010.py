"""Observe signed HTTP session admission at a registry key's expiry boundary."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from test_completion010 import Actor, ROOT, canonical, digest, independent
from test_http_session010 import audit, body


def revision(root):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', required=True, type=Path)
    parser.add_argument('--adapter', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expected-revision')
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT / 'docs/evidence' in (output, *output.parents):
        parser.error('preserve historical evidence')
    go_root, adapter = args.go_root.resolve(), args.adapter.resolve()
    fixture_path = ROOT / 'vectors/0.10.0/http-registry-expiry010.json'
    fixture = json.loads(fixture_path.read_text())
    assert fixture['schema_version'] == 1 and fixture['kind'] == 'http-registry-signing-key-expiry'
    assert fixture['key_expires'] == fixture['at_expiry_unix'] == fixture['before_unix'] + 1
    assert fixture['control_key_expires'] == fixture['at_expiry_unix'] + 1
    actual_revision = revision(go_root)
    if args.expected_revision:
        assert actual_revision == args.expected_revision, 'unexpected Go core revision'
    assert not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=go_root), 'modified Go core source'
    output.mkdir(parents=True, exist_ok=False)
    report = {
        'schema_version': 1,
        'kind': fixture['kind'],
        'status': 'RUNNING',
        'conformance': 'NOT_ESTABLISHED',
        'scope': fixture['scope'],
        'fixture_sha256': digest(fixture_path),
        'inspector_revision': revision(ROOT),
        'go_revision': actual_revision,
        'adapter_sha256': digest(adapter),
        'observations': [],
        'raw': 'raw.jsonl',
    }

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    with (output / 'raw.jsonl').open('w') as raw:
        def log(value):
            raw.write(json.dumps(value, sort_keys=True) + '\n')
            raw.flush()

        try:
            with tempfile.TemporaryDirectory() as state:
                alice = Actor('alice', 'alice', Path(state) / 'alice', adapter, log, fixture['key_expires'])
                bob = Actor('bob', 'bob', Path(state) / 'bob', adapter, log, fixture['key_expires'])
                try:
                    initiation = bytes.fromhex(alice.call('start')['wire_hex'])
                    completion = bytes.fromhex(bob.call('respond', wire_hex=initiation.hex())['wire_hex'])
                    alice.call('complete', wire_hex=completion.hex())
                    independent(initiation, completion)
                    alice.call('http-bind')
                    bob.call('http-bind')

                    first = json.loads(bytes.fromhex(alice.call(
                        'http-request-seal', wire_hex=fixture['before_request'].encode().hex()
                    )['wire_hex']))
                    first_base = audit(first, 1)
                    first_result = bob.call('http-request-open', wire_hex=canonical(first).hex())
                    assert bytes.fromhex(first_result['plaintext_hex']) == fixture['before_request'].encode()
                    assert bob.call('record-inspect') == {
                        'state': 'ESTABLISHED', 'reservations': fixture['expected']['accepted_replay_reservations']
                    }
                    report['observations'].append({
                        'case': 'before-expiry', 'verdict': 'ACCEPT',
                        'signature_base_sha256': first_base,
                    })
                    save()

                    second = json.loads(bytes.fromhex(alice.call(
                        'http-request-seal', wire_hex=fixture['after_request'].encode().hex()
                    )['wire_hex']))
                    second_base = audit(second, 1)
                    first_body, second_body = json.loads(body(first)), json.loads(body(second))
                    assert first_body['id'] != second_body['id'] and first_body['nonce'] != second_body['nonce']
                    bob.call('http-request-open', 'REJECT', wire_hex=canonical(second).hex(),
                             unix=fixture['at_expiry_unix'], mono_ms=1000)
                    after = bob.call('record-inspect')
                    assert after == {
                        'state': fixture['expected']['state_after_expiry'],
                        'reservations': fixture['expected']['accepted_replay_reservations'],
                    }
                    report['observations'].append({
                        'case': 'at-expiry', 'verdict': 'REJECT',
                        'signature_base_sha256': second_base,
                        'state': after['state'], 'replay_reservations': after['reservations'],
                    })
                    report['status'] = 'PASS'
                finally:
                    try:
                        alice.close()
                    finally:
                        bob.close()

                control_alice = Actor('control-alice', 'alice', Path(state) / 'control-alice',
                                      adapter, log, fixture['control_key_expires'])
                control_bob = Actor('control-bob', 'bob', Path(state) / 'control-bob',
                                    adapter, log, fixture['control_key_expires'])
                try:
                    initiation = bytes.fromhex(control_alice.call('start')['wire_hex'])
                    completion = bytes.fromhex(control_bob.call(
                        'respond', wire_hex=initiation.hex()
                    )['wire_hex'])
                    control_alice.call('complete', wire_hex=completion.hex())
                    independent(initiation, completion)
                    control_alice.call('http-bind')
                    control_bob.call('http-bind')
                    request = json.loads(bytes.fromhex(control_alice.call(
                        'http-request-seal', wire_hex=fixture['after_request'].encode().hex()
                    )['wire_hex']))
                    control_base = audit(request, 1)
                    result = control_bob.call('http-request-open', wire_hex=canonical(request).hex(),
                                              unix=fixture['at_expiry_unix'], mono_ms=1000)
                    assert bytes.fromhex(result['plaintext_hex']) == fixture['after_request'].encode()
                    assert control_bob.call('record-inspect') == {
                        'state': 'ESTABLISHED', 'reservations': 1,
                    }
                    report['observations'].append({
                        'case': 'before-control-expiry', 'verdict': 'ACCEPT',
                        'signature_base_sha256': control_base,
                    })
                    report['status'] = 'PASS'
                finally:
                    try:
                        control_alice.close()
                    finally:
                        control_bob.close()

                revoked_alice = Actor('revoked-alice', 'alice', Path(state) / 'revoked-alice',
                                      adapter, log, fixture['control_key_expires'])
                revoked_bob = Actor('revoked-bob', 'bob', Path(state) / 'revoked-bob',
                                    adapter, log, fixture['control_key_expires'])
                try:
                    initiation = bytes.fromhex(revoked_alice.call('start')['wire_hex'])
                    completion = bytes.fromhex(revoked_bob.call(
                        'respond', wire_hex=initiation.hex()
                    )['wire_hex'])
                    revoked_alice.call('complete', wire_hex=completion.hex())
                    independent(initiation, completion)
                    revoked_alice.call('http-bind')
                    revoked_bob.call('http-bind')
                    first = json.loads(bytes.fromhex(revoked_alice.call(
                        'http-request-seal', wire_hex=fixture['before_request'].encode().hex()
                    )['wire_hex']))
                    audit(first, 1)
                    first_result = revoked_bob.call('http-request-open', wire_hex=canonical(first).hex())
                    assert bytes.fromhex(first_result['plaintext_hex']) == fixture['before_request'].encode()
                    second = json.loads(bytes.fromhex(revoked_alice.call(
                        'http-request-seal', wire_hex=fixture['after_request'].encode().hex()
                    )['wire_hex']))
                    revoked_base = audit(second, 1)
                    revoked_bob.call('http-request-open', 'REJECT',
                                     wire_hex=canonical(second).hex(), mode='revoke-init')
                    assert revoked_bob.call('record-inspect') == {
                        'state': 'CLOSED', 'reservations': 1,
                    }
                    report['observations'].append({
                        'case': 'revoked-after-first-request', 'verdict': 'REJECT',
                        'signature_base_sha256': revoked_base,
                        'state': 'CLOSED', 'replay_reservations': 1,
                    })
                    report['status'] = 'PASS'
                finally:
                    try:
                        revoked_alice.close()
                    finally:
                        revoked_bob.close()
        except Exception as exc:
            report['status'], report['reason'] = 'FAIL', str(exc)
            raise
        finally:
            raw.flush()
            report['raw_sha256'] = hashlib.sha256((output / 'raw.jsonl').read_bytes()).hexdigest()
            save()
    print('Four Go HTTP session expiry and revocation observations passed')


if __name__ == '__main__':
    main()
