"""Compare signed result consumption through captured Go/Rust Client APIs."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from inspect_captured_client_parity import (FIXTURE, GO_REVISION, HEADER,
                                            NORMATIVE_REVISION, OUTER, ROOT,
                                            RUST_REVISION, RUST_SOURCE, GO_SOURCE,
                                            build, canonical, check_journal,
                                            check_source, observe, sha,
                                            signed_fixture)

SIGNATURE_ORACLE = ROOT / 'scripts/check_guard_results010.js'


def reply(**values):
    return dict({'ok': True, 'id': '', 'intent_hex': '', 'status': '',
                 'first': False, 'ignored': False, 'output_hex': '',
                 'handoffs': 0}, **values)


def check_replies(rows, expected):
    if rows != expected:
        raise ValueError('captured Client result observations differ')


def outer(number):
    return f'00000000-0000-4000-8000-{number:012d}'


def result_fixture(intent_hex, status='completed', output=None, digest=None):
    raw = bytes.fromhex(intent_hex)
    intent = json.loads(raw)['intent']
    seed = hashlib.sha256(b'public Guard fixture executor').digest()
    signer = Ed25519PrivateKey.from_private_bytes(seed)
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    approved = json.loads(FIXTURE.read_bytes())['public_key_hex']
    if public != approved:
        raise ValueError('fixture result signer identity')
    result = {
        'version': '0.10.0', 'request_id': intent['request_id'],
        'call_id': intent['call_id'], 'issuer': intent['recipient'],
        'recipient': intent['issuer'], 'created': 1700000000,
        'expires': 1700000300, 'keyid': intent['recipient'] + '#signing-1',
        'alg': 'ed25519', 'intent_digest': sha(raw) if digest is None else digest,
        'status': status, 'output': {} if output is None else output,
    }
    message = b'sage-tool-result|0.10.0\0' + canonical(result)
    proof = signer.sign(message)
    signer.public_key().verify(proof, message)
    envelope = {'result': result,
                'proof': base64.urlsafe_b64encode(proof).rstrip(b'=').decode()}
    return canonical(envelope).hex()


def event(kind, id='', at=0, intent_hex='', result_hex=''):
    return {'kind': kind, 'id': id, 'at': at,
            'intent_hex': intent_hex, 'result_hex': result_hex}


def journal_hash(events):
    line = lambda row: json.dumps(row, separators=(',', ':')).encode() + b'\n'
    return sha(HEADER + b''.join(line(row) for row in events))


def fixture_commands():
    config, public, original, fixture_hash, vector_hash = signed_fixture()
    command = {'action': 'open_captured', 'input': config,
               'public_key_hex': public, 'utc': 1700000000000, 'mono': 0,
               'capture_items_hex': original['items_hex'],
               'capture_request_id': original['request_id']}
    intent_hex = config['envelope_hex']
    completed = result_fixture(intent_hex, output={'value': 'ok'})
    pending = result_fixture(intent_hex, status='pending')
    wrong = result_fixture(intent_hex, output={'value': 'ok'}, digest='0' * 64)
    broken = json.loads(bytes.fromhex(completed))
    proof = bytearray(base64.urlsafe_b64decode(broken['proof'] + '=='))
    proof[0] ^= 1
    broken['proof'] = base64.urlsafe_b64encode(bytes(proof)).rstrip(b'=').decode()
    invalid = canonical(broken).hex()
    return command, {'completed': completed, 'pending': pending,
                     'wrong-intent': wrong, 'invalid-proof': invalid}, \
        fixture_hash, vector_hash


def observation(binary, path, mode, commands, events):
    rows = observe(binary, path, mode, commands, True)
    raw = check_journal(path, events)
    return rows, sha(raw)


def inspect(go_root, rust_root):
    go_root = check_source(go_root, GO_REVISION)
    rust_root = check_source(rust_root, RUST_REVISION)
    command, results, fixture_hash, vector_hash = fixture_commands()
    intent_hex = command['input']['envelope_hex']
    audit = {'public_key_hex': command['public_key_hex'], 'cases': [
        {'envelope_hex': results[name], 'intent_hex': intent_hex,
         'status': name, 'output': {'value': 'ok'} if name == 'completed' else {},
         'created': 1700000000} for name in ('pending', 'completed')]}
    verification = subprocess.run(['node', str(SIGNATURE_ORACLE)],
        input=canonical(audit), capture_output=True, timeout=10, check=True)
    if verification.stderr or json.loads(verification.stdout) != {'status': 'PASS', 'checks': 2}:
        raise ValueError('independent result signature audit')
    start = [event('open', intent_hex=intent_hex),
             event('send', OUTER, 1700000000000)]
    close = event('close', OUTER)
    completed_events = start + [close, event('terminal', OUTER,
                                             result_hex=results['completed'])]
    reject_events = start + [close]
    pending_events = start + [close, event('send', outer(2), 1700000001000),
                              event('close', outer(2)),
                              event('terminal', outer(2),
                                    result_hex=results['completed'])]
    with tempfile.TemporaryDirectory(prefix='sage-captured-result-') as directory:
        root = Path(directory)
        binaries = build(root, go_root, rust_root)
        cases, terminals = [], {}
        for language, binary in binaries.items():
            path = root / f'{language}-completed'
            rows, digest = observation(binary, path, 'create',
                [command, {'action': 'begin', 'id': OUTER},
                 {'action': 'accept', 'id': OUTER,
                  'envelope_hex': results['completed']},
                 {'action': 'accept', 'id': OUTER,
                  'envelope_hex': results['completed']}, {'action': 'close'}],
                completed_events)
            check_replies(rows, [reply(), reply(id=OUTER, intent_hex=intent_hex, handoffs=1),
                reply(status='completed', first=True,
                      output_hex=canonical({'value': 'ok'}).hex(), handoffs=1),
                reply(ok=False, handoffs=1), reply(handoffs=1)])
            terminals[language] = path
            cases.append({'id': f'{language}-completed', 'status': 'PASS',
                          'journal_sha256': digest, 'output_releases': 1,
                          'handoffs': 1})
            for label in ('wrong-intent', 'invalid-proof'):
                path = root / f'{language}-{label}'
                rows, digest = observation(binary, path, 'create',
                    [command, {'action': 'begin', 'id': OUTER},
                     {'action': 'accept', 'id': OUTER,
                      'envelope_hex': results[label]}, {'action': 'close'}],
                    reject_events)
                check_replies(rows, [reply(),
                    reply(id=OUTER, intent_hex=intent_hex, handoffs=1),
                    reply(ok=False, handoffs=1), reply(handoffs=1)])
                cases.append({'id': f'{language}-{label}', 'status': 'PASS',
                              'journal_sha256': digest, 'output_releases': 0,
                              'handoffs': 1})
            path = root / f'{language}-pending'
            rows, digest = observation(binary, path, 'create',
                [command, {'action': 'begin', 'id': OUTER},
                 {'action': 'accept', 'id': OUTER,
                  'envelope_hex': results['pending']},
                 {'action': 'tick', 'utc': 1700000001000, 'mono': 1000},
                 {'action': 'begin', 'id': outer(2)},
                 {'action': 'accept', 'id': outer(2),
                  'envelope_hex': results['completed']}, {'action': 'close'}],
                pending_events)
            check_replies(rows, [reply(), reply(id=OUTER, intent_hex=intent_hex, handoffs=1),
                reply(status='pending', handoffs=1), reply(handoffs=1),
                reply(id=outer(2), intent_hex=intent_hex, handoffs=2),
                reply(status='completed', first=True,
                      output_hex=canonical({'value': 'ok'}).hex(), handoffs=2),
                reply(handoffs=2)])
            cases.append({'id': f'{language}-pending-then-completed',
                          'status': 'PASS', 'journal_sha256': digest,
                          'output_releases': 1, 'handoffs': 2})
        for writer, reader in (('go', 'rust'), ('rust', 'go')):
            path = terminals[writer]
            before = path.read_bytes()
            later = dict(command, utc=1700000001000)
            rows, digest = observation(binaries[reader], path, 'reopen',
                [later, {'action': 'begin', 'id': outer(2)},
                 {'action': 'accept', 'id': OUTER,
                  'envelope_hex': results['completed']},
                 {'action': 'close'}], completed_events)
            check_replies(rows, [reply(), reply(ok=False), reply(ok=False), reply()])
            if path.read_bytes() != before:
                raise ValueError('cross-language terminal result redelivery')
            cases.append({'id': f'{writer}-to-{reader}-terminal-reopen',
                          'status': 'PASS', 'journal_sha256': digest,
                          'output_releases': 0, 'handoffs': 0})
    return {'schema_version': 1, 'kind': 'captured-client-signed-result-parity',
            'protocol_version': '0.10.0',
            'normative_source_revision': NORMATIVE_REVISION,
            'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
            'fixture_sha256': fixture_hash, 'vector_sha256': vector_hash,
            'signature_checks': 2, 'signature_oracle_sha256': sha(SIGNATURE_ORACLE.read_bytes()),
            'go_adapter_sha256': sha((GO_SOURCE / 'main.go.txt').read_bytes() +
                                     (GO_SOURCE / 'fixtures.go.txt').read_bytes()),
            'rust_adapter_sha256': sha(RUST_SOURCE.read_bytes()),
            'status': 'SIGNED_RESULT_API_PARITY', 'deployed_host': 'NOT_RUN',
            'full_protocol_conformance': 'NOT_ESTABLISHED', 'cases': cases}


def check_report(report):
    command, results, fixture_hash, vector_hash = fixture_commands()
    expected = {'schema_version': 1,
                'kind': 'captured-client-signed-result-parity',
                'protocol_version': '0.10.0',
                'normative_source_revision': NORMATIVE_REVISION,
                'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
                'fixture_sha256': fixture_hash, 'vector_sha256': vector_hash,
                'signature_checks': 2, 'signature_oracle_sha256': sha(SIGNATURE_ORACLE.read_bytes()),
                'go_adapter_sha256': sha((GO_SOURCE / 'main.go.txt').read_bytes() +
                                         (GO_SOURCE / 'fixtures.go.txt').read_bytes()),
                'rust_adapter_sha256': sha(RUST_SOURCE.read_bytes()),
                'status': 'SIGNED_RESULT_API_PARITY', 'deployed_host': 'NOT_RUN',
                'full_protocol_conformance': 'NOT_ESTABLISHED'}
    if set(report) != set(expected) | {'cases'} or \
            any(report[key] != value for key, value in expected.items()):
        raise ValueError('signed result report scope or provenance')
    intent = command['input']['envelope_hex']
    start = [event('open', intent_hex=intent),
             event('send', OUTER, 1700000000000)]
    complete = journal_hash(start + [event('close', OUTER),
        event('terminal', OUTER, result_hex=results['completed'])])
    rejected = journal_hash(start + [event('close', OUTER)])
    pending = journal_hash(start + [event('close', OUTER),
        event('send', outer(2), 1700000001000), event('close', outer(2)),
        event('terminal', outer(2), result_hex=results['completed'])])
    cases = []
    for language in ('go', 'rust'):
        for label, digest, releases, sends in (
                ('completed', complete, 1, 1),
                ('wrong-intent', rejected, 0, 1),
                ('invalid-proof', rejected, 0, 1),
                ('pending-then-completed', pending, 1, 2)):
            cases.append({'id': f'{language}-{label}', 'status': 'PASS',
                          'journal_sha256': digest,
                          'output_releases': releases, 'handoffs': sends})
    for writer, reader in (('go', 'rust'), ('rust', 'go')):
        cases.append({'id': f'{writer}-to-{reader}-terminal-reopen',
                      'status': 'PASS', 'journal_sha256': complete,
                      'output_releases': 0, 'handoffs': 0})
    if report['cases'] != cases:
        raise ValueError('signed result case verdicts or journal bytes')
    return len(cases)


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
        report = json.loads((ROOT / 'docs/evidence/captured-client-results.json').read_text())
        check_report(report)
    print(json.dumps({'cases': len(report['cases']), 'status': report['status'],
                      'deployed_host': report['deployed_host']}))


if __name__ == '__main__':
    main()
