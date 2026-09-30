"""Observe one administrator journal write against a fresh public HTTPS read."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import revision
from observe_reconciled_reg08_admin_mtls import (
    certificates, encode, openssl, run_case,
)
from observe_reconciled_reg08_transition_shape import (
    PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)

VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-public-binding.json'
VECTOR_SHA256 = '16c34c7393970359415aefe8ef2efb127f4f07c04816fd2caa8f21dc610397ba'
GO_REVISION = '34c288188c5003ed80d24c7d1e81d123613b0ba3'
RUST_REVISION = '0d0496019cfa93473745a9edf75b6b9062b73e7b'
ORIGIN = 'https://agents.example.com'
EXPECTED = {
    'matching-public-record': 'MATCH',
    'different-public-record': 'RECORD_STALE',
    'unbound-admin-source': 'RECORD_UNREACHABLE',
    'unapproved-origin': 'RECORD_UNREACHABLE',
    'unapproved-destination': 'RECORD_UNREACHABLE',
    'wrong-tls-name': 'RECORD_UNREACHABLE',
    'untrusted-tls-root': 'RECORD_UNREACHABLE',
}


def public_certificate(directory, name, hostname):
    key = directory / f'{name}.key'
    csr = directory / f'{name}.csr'
    cert = directory / f'{name}.pem'
    extensions = directory / f'{name}.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\n'
                          f'subjectAltName=DNS:{hostname}\n')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-noenc',
            '-subj', f'/CN={hostname}', '-keyout', key, '-out', csr)
    openssl('x509', '-req', '-in', csr, '-CA', directory / 'ca.pem',
            '-CAkey', directory / 'ca.key', '-CAcreateserial', '-days', '1',
            '-out', cert, '-extfile', extensions)
    return cert, key


def serve_once(cert, key, body):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(15)
    address = listener.getsockname()
    failures = []

    def worker():
        try:
            client, _ = listener.accept()
            with client:
                client.settimeout(10)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(cert), str(key))
                with context.wrap_socket(client, server_side=True) as tls:
                    request = b''
                    while b'\r\n\r\n' not in request and len(request) <= 4096:
                        part = tls.recv(4096)
                        if not part:
                            break
                        request += part
                    require(request.startswith(b'GET /.well-known/sage/agents/billing-bot HTTP/1.1\r\n'),
                            'unexpected public Registry target')
                    header = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                              'Cache-Control: no-store\r\nContent-Length: '
                              f'{len(body)}\r\n\r\n').encode()
                    tls.sendall(header + body)
        except (OSError, ssl.SSLError, ValueError) as error:
            failures.append(str(error))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return address[1], thread, failures


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-public-go'
    environment = os.environ.copy()
    environment['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-public-binding010'], cwd=go_root,
                   env=environment, check=True, timeout=300)
    lock = rust_root / 'Cargo.lock'
    if lock.exists():
        require(sha(lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_public_binding010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    return {'go': go_binary,
            'rust': target / 'debug' / 'examples' / 'registry_web_public_binding010'}


def build_admin(name, go_root, rust_root, directory):
    if name == 'go':
        binary = directory / 'sage-reg08-admin-go'
        environment = os.environ.copy()
        environment['GOCACHE'] = str(directory / 'go-cache')
        subprocess.run(['go', 'build', '-o', str(binary),
                        './examples/registry-web-admin-mtls010'],
                       cwd=go_root, env=environment, check=True, timeout=300)
        return binary
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_admin_mtls010', '--target-dir',
                    str(directory / 'rust-target')], cwd=rust_root,
                   check=True, timeout=600)
    return directory / 'rust-target' / 'debug' / 'examples' / 'registry_web_admin_mtls010'


def public_body(base, kind, now):
    record = copy.deepcopy(base['body']['record'])
    record.update(state='created', version='1')
    if kind == 'different':
        record.update(state='active', version='2')
    return json.dumps({'record': record, 'issued': now, 'expires': now + 5},
                      separators=(',', ':')).encode()


def run_public(binary, journal, row, base, certs, cert_paths, directory):
    now = 100
    policy = row['policy']
    if row['public_record'] != 'none':
        cert, key = cert_paths['wrong' if policy == 'wrong-name' else 'valid']
        port, thread, failures = serve_once(cert, key,
                                            public_body(base, row['public_record'], now))
    else:
        port, thread, failures = 443, None, []
    destination = f'127.0.0.1:{port}'
    root = certs['root_der']
    if policy == 'untrusted-root':
        foreign = directory / 'foreign-root.der'
        openssl('x509', '-in', directory / 'foreign-ca.pem',
                '-outform', 'DER', '-out', foreign)
        root = foreign.read_bytes()
    cfg = {
        'journal_path': str(journal), 'did': base['expected_did'],
        'source': row['admin_source'],
        'allowed_origins': [] if policy == 'no-origin' else [ORIGIN],
        'destination': destination,
        'allowed_destinations': [] if policy == 'no-destination' else [destination],
        'root': encode(root), 'now': now,
    }
    completed = subprocess.run([str(binary)], input=json.dumps(cfg), text=True,
                               capture_output=True, timeout=30, check=True)
    require(not completed.stderr, 'public adapter diagnostic output')
    result = json.loads(completed.stdout)
    require(type(result) is dict and set(result) == {'verdict'} and
            type(result['verdict']) is str, 'public adapter result')
    if thread is not None:
        thread.join(timeout=16)
        require(not thread.is_alive(), 'public server did not finish')
        if policy == 'approved':
            require(not failures, 'public server failed: ' + str(failures))
    return result['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 public binding fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-public-journal-subcondition-vectors' and
            suite['rule_id'] == 'REG-08' and
            suite['protocol_version'] == '0.10.0' and
            [row['id'] for row in suite['cases']] == list(EXPECTED),
            'public binding suite identity')
    for row in suite['cases']:
        require(set(row) == {'id', 'admin_source', 'public_record', 'policy',
                             'expected'} and row['expected'] == EXPECTED[row['id']] and
                row['admin_source'] in {ORIGIN, 'other-origin'} and
                row['public_record'] in {'created', 'different', 'none'} and
                row['policy'] in {'approved', 'no-origin', 'no-destination',
                                  'wrong-name', 'untrusted-root'},
                'public binding case fields')
    require(sha((root / PROOFS).read_bytes()) == PROOFS_SHA256,
            'proof fixture changed')
    base = json.loads((root / PROOFS).read_bytes())['base']
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-public-binding-') as temporary:
        directory = Path(temporary)
        certs = certificates(directory)
        cert_paths = {
            'valid': public_certificate(directory, 'public', 'agents.example.com'),
            'wrong': public_certificate(directory, 'wrong', 'other.example.com'),
        }
        binaries = build(go_root, rust_root, directory, lock_source)
        subjects = {}
        for name, binary in binaries.items():
            admin_binary = build_admin(name, go_root, rust_root, directory)
            cases = []
            for row in suite['cases']:
                journal = directory / f'{name}-{row["id"]}.journal'
                admin_row = {'id': 'controller-create', 'mode': 'controller-create',
                             'client': 'client', 'actor': 'operator',
                             'source': row['admin_source'], 'now': 100}
                admin = run_case(admin_binary, base, admin_row, certs, journal)
                require(admin == {'verdict': 'TRANSITION_ACCEPT', 'committed': True},
                        'administrator write was not committed')
                actual = run_public(binary, journal, row, base, certs,
                                    cert_paths, directory)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {'source_revision': revisions[name],
                              'matched': sum(item['match'] for item in cases),
                              'total': len(cases), 'cases': cases,
                              'executable_sha256': sha(binary.read_bytes())}
    require(all(item['matched'] == 7 for item in subjects.values()),
            'core public binding mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-public-journal-binding-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'public_journal_snapshot_match': 'BOUNDED',
        'deployed_storage_binding': 'NOT_RUN',
        'production_admin_framing': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
        'remote_atomic_write': 'NOT_RUN',
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
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
    except (ValueError, KeyError, TypeError, OSError, IndexError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, 'REG-08 public binding observation FAIL: ' + str(error) + '\n')
    print('REG-08 public binding: Go 7/7, Rust 7/7; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
