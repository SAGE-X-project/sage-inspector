"""Observe verified mTLS controller writes in pinned Go and Rust local adapters."""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
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
from observe_reconciled_reg08_transition_shape import (
    PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)

VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-admin-mtls.json'
VECTOR_SHA256 = '994aaed8e5146ed5e24fddc74c0c46ae1145217317042a5358cfbf99d537f580'
GO_REVISION = 'c6764c226da2abc61f089b1ffd723a027aa2d54d'
RUST_REVISION = '0c8eefcf7b66275e912eafb2497a04b8548cf464'
EXPECTED = {
    'controller-create': ('TRANSITION_ACCEPT', True),
    'missing-certificate': ('WRITE_REJECTED', False),
    'unrecognized-certificate': ('WRITE_REJECTED', False),
    'untrusted-certificate-root': ('WRITE_REJECTED', False),
    'wrong-controller': ('WRITE_REJECTED', False),
    'source-mismatch': ('RECORD_UNREACHABLE', False),
    'controller-activate': ('TRANSITION_ACCEPT', True),
    'stale-version': ('RECORD_STALE', False),
}


def expectation(mode):
    verdict, committed = EXPECTED[mode]
    return {'verdict': verdict, 'committed': committed}


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], capture_output=True,
                   check=True, timeout=20)


def certificates(directory):
    ca_key, ca_pem = directory / 'ca.key', directory / 'ca.pem'
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
            '-subj', '/CN=SAGE local admin CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', ca_key, '-out', ca_pem)

    def issue(name, hostname, use, issuer_pem=ca_pem, issuer_key=ca_key):
        key, csr = directory / (name + '.key'), directory / (name + '.csr')
        cert, der = directory / (name + '.pem'), directory / (name + '.der')
        extensions = directory / (name + '.ext')
        extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature,keyEncipherment\n'
                              f'extendedKeyUsage={use}\n'
                              f'subjectAltName=DNS:{hostname}\n')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-noenc',
                '-subj', f'/CN={hostname}', '-keyout', key, '-out', csr)
        openssl('x509', '-req', '-in', csr, '-CA', issuer_pem, '-CAkey', issuer_key,
                '-CAcreateserial', '-days', '1', '-out', cert, '-extfile', extensions)
        openssl('x509', '-in', cert, '-outform', 'DER', '-out', der)
        return cert, key, der.read_bytes()

    server = issue('server', 'admin.example.com', 'serverAuth')
    client = issue('client', 'operator.example.com', 'clientAuth')
    other = issue('other', 'other.example.com', 'clientAuth')
    foreign_ca_key = directory / 'foreign-ca.key'
    foreign_ca_pem = directory / 'foreign-ca.pem'
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
            '-subj', '/CN=SAGE unrelated admin CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', foreign_ca_key, '-out', foreign_ca_pem)
    foreign = issue('foreign', 'foreign.example.com', 'clientAuth',
                    foreign_ca_pem, foreign_ca_key)
    key_der = directory / 'server-key.der'
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', server[1],
            '-outform', 'DER', '-out', key_der)
    root_der = directory / 'ca.der'
    openssl('x509', '-in', ca_pem, '-outform', 'DER', '-out', root_der)
    return {
        'ca_pem': ca_pem, 'root_der': root_der.read_bytes(),
        'server_cert': server[2], 'server_key': key_der.read_bytes(),
        'client_cert': client[0], 'client_key': client[1],
        'client_pin': hashlib.sha256(client[2]).hexdigest(),
        'other_cert': other[0], 'other_key': other[1],
        'foreign_cert': foreign[0], 'foreign_key': foreign[1],
    }


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def request(base, row):
    created = copy.deepcopy(base['body']['record'])
    created.update(state='created', version='1')
    active = copy.deepcopy(created)
    active.update(state='active', version='2')
    terminal = copy.deepcopy(active)
    terminal.update(state='deactivated', version='3')
    mode = row['mode']
    if mode == 'controller-create':
        record, operation, version = created, 'create', ''
    elif mode in {'stale-version'}:
        record, operation, version = terminal, 'deactivate', '1'
    else:
        record, operation, version = active, 'activate', '1'
    now = row['now']
    candidate = json.dumps({'record': record, 'issued': now, 'expires': now + 5},
                           separators=(',', ':')).encode()
    return json.dumps({'candidate': encode(candidate), 'operation': operation,
                       'expected_version': version}, separators=(',', ':')) + '\n'


def configuration(base, row, certs, journal_path):
    return json.dumps({
        'server_cert': encode(certs['server_cert']),
        'server_key': encode(certs['server_key']),
        'client_root': encode(certs['root_der']),
        'client_pin': certs['client_pin'],
        'actor': row['actor'], 'journal_path': str(journal_path),
        'did': base['expected_did'], 'source': row['source'],
        'now': row['now'], 'create': row['mode'] == 'controller-create',
    }, separators=(',', ':'))


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-admin-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-admin-mtls010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_admin_mtls010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_web_admin_mtls010'
    require(go_binary.is_file() and rust_binary.is_file(), 'mTLS adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def read_line(stream, timeout=15):
    result = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: result.put(stream.readline()),
                     daemon=True).start()
    return result.get(timeout=timeout)


def run_case(binary, base, row, certs, journal_path):
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        process.stdin.write(configuration(base, row, certs, journal_path))
        process.stdin.close()
        port_line = read_line(process.stdout)
        require(port_line.startswith('PORT ') and port_line[5:].strip().isdigit(),
                'mTLS adapter did not listen: ' + row['id'])
        port = int(port_line[5:].strip())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(certs['ca_pem']))
        client = row['client']
        if client != 'none':
            context.load_cert_chain(str(certs[client + '_cert']),
                                    str(certs[client + '_key']))
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname='admin.example.com') as tls:
                    tls.sendall(request(base, row).encode())
        except (ssl.SSLError, OSError):
            pass  # The adapter's authenticated verdict is still required.
        output = read_line(process.stdout)
        process.wait(timeout=15)
        stderr = process.stderr.read()
        require(process.returncode == 0 and not stderr and
                len(output) <= 256, 'mTLS adapter failed: ' + row['id'])
        actual = json.loads(output)
        require(type(actual) is dict and set(actual) == {'verdict', 'committed'} and
                type(actual['verdict']) is str and type(actual['committed']) is bool,
                'mTLS adapter result: ' + row['id'])
        return actual
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 mTLS fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-local-admin-mtls-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'mTLS suite identity')
    require([row['mode'] for row in suite['cases']] == list(EXPECTED),
            'mTLS case order')
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'client', 'actor', 'source', 'now', 'expected'} and
                row['id'] == row['mode'] and
                row['client'] in {'client', 'other', 'foreign', 'none'} and
                row['actor'] in {'operator', 'assistant'} and
                row['source'] in {'trusted-web-origin', 'other-origin'} and
                type(row['now']) is int and
                row['expected'] == expectation(row['mode']), 'mTLS case fields')
    proof_raw = (root / PROOFS).read_bytes()
    require(sha(proof_raw) == PROOFS_SHA256, 'proof fixture changed')
    base = json.loads(proof_raw)['base']
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-admin-mtls-') as temporary:
        output = Path(temporary)
        certs = certificates(output)
        binaries = build(go_root, rust_root, output, lock_source)
        subjects = {}
        for name, binary in binaries.items():
            journal_path = output / (name + '.journal')
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, base, row, certs, journal_path)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {'source_revision': revisions[name],
                              'executable_sha256': sha(binary.read_bytes()),
                              'matched': sum(case['match'] for case in cases),
                              'total': len(cases), 'cases': cases}
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core mTLS admin mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-local-admin-mtls-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'controller_credential_binding': 'BOUNDED',
        'deployed_public_source_binding': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
        'production_admin_framing': 'NOT_RUN',
        'remote_atomic_write': 'NOT_RUN',
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
            subprocess.SubprocessError, json.JSONDecodeError, queue.Empty) as error:
        parser.exit(1, 'REG-08 mTLS admin observation FAIL: ' + str(error) + '\n')
    print('REG-08 local mTLS admin: Go 8/8, Rust 8/8; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
