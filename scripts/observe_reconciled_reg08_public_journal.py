"""Observe HTTPS records produced from the same durable administrator journal."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import revision
from observe_reconciled_reg08_admin_mtls import (
    certificates, encode, openssl, read_line, run_case,
)
from observe_reconciled_reg08_public_binding import public_certificate
from observe_reconciled_reg08_transition_shape import (
    PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)

VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-public-journal.json'
VECTOR_SHA256 = 'c066ba68494e6519922a2298e63efc90dc1551ed8d8c91a4ad4a9dcc24f58913'
GO_REVISION = '8038e1906f9b7595a0589584fdc707fd3f9e2ce1'
RUST_REVISION = '6f16f85c334297ce348c395edd5d6c9462c1d3e8'
ORIGIN = 'https://agents.example.com'
EXPECTED = {
    'created-record-published': 'RECORD_ACCEPT',
    'active-record-published': 'RECORD_ACCEPT',
    'wrong-public-source': 'RECORD_UNREACHABLE',
    'wrong-public-did': 'RECORD_UNREACHABLE',
    'missing-committed-journal': 'RECORD_UNREACHABLE',
}


def public_certificate_der(directory):
    cert, key = public_certificate(directory, 'public-journal', 'agents.example.com')
    cert_der = directory / 'public-journal.der'
    key_der = directory / 'public-journal-key.der'
    openssl('x509', '-in', cert, '-outform', 'DER', '-out', cert_der)
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', key,
            '-outform', 'DER', '-out', key_der)
    return cert_der.read_bytes(), key_der.read_bytes()


def build(go_root, rust_root, output, lock_source):
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    go = {}
    for name, path in {
        'admin': './examples/registry-web-admin-mtls010',
        'publisher': './examples/registry-web-public-journal010',
        'fetcher': './examples/registry-web-http-record010',
    }.items():
        binary = output / f'go-{name}'
        subprocess.run(['go', 'build', '-o', str(binary), path], cwd=go_root,
                       env=go_env, check=True, timeout=300)
        go[name] = binary
    lock = rust_root / 'Cargo.lock'
    if lock.exists():
        require(sha(lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--target-dir', str(target),
                    '--example', 'registry_web_admin_mtls010',
                    '--example', 'registry_web_public_journal010',
                    '--example', 'registry_web_http_record010'],
                   cwd=rust_root, check=True, timeout=600)
    rust = {name: target / 'debug' / 'examples' / example for name, example in {
        'admin': 'registry_web_admin_mtls010',
        'publisher': 'registry_web_public_journal010',
        'fetcher': 'registry_web_http_record010',
    }.items()}
    return {'go': go, 'rust': rust}


def publisher_config(journal, row, base, cert_der, key_der):
    did = base['expected_did']
    if row['publisher_did'] == 'other':
        did = 'did:sage:web:agents.example.com:other-bot'
    return {
        'server_cert': encode(cert_der), 'server_key': encode(key_der),
        'journal_path': str(journal), 'did': did,
        'source': row['publisher_source'], 'now': row['now'],
    }


def start_publisher(binary, config):
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        process.stdin.write(json.dumps(config))
        process.stdin.close()
        first = read_line(process.stdout)
        if first.startswith('PORT ') and first[5:].strip().isdigit():
            return process, int(first[5:].strip())
        verdict = json.loads(first)
        require(verdict == {'verdict': 'RECORD_UNREACHABLE'},
                'publisher opened an invalid journal binding')
        process.wait(timeout=10)
        require(process.returncode == 0 and not process.stderr.read(),
                'publisher failed before listening')
        return None, None
    except Exception:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        raise


def finish_publisher(process):
    try:
        output = read_line(process.stdout)
        process.wait(timeout=15)
        require(process.returncode == 0 and not process.stderr.read() and
                json.loads(output) == {'verdict': 'PUBLISHED'},
                'publisher did not serve the committed journal')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def python_fetch(port, ca_pem):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(ca_pem))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname='agents.example.com') as tls:
            tls.settimeout(10)
            tls.sendall(b'GET /.well-known/sage/agents/billing-bot HTTP/1.1\r\n'
                        b'Host: agents.example.com\r\nAccept: application/json\r\n'
                        b'Cache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n')
            chunks = []
            while True:
                part = tls.recv(8192)
                if not part:
                    break
                chunks.append(part)
                require(sum(map(len, chunks)) <= 80_000, 'public response too large')
    head, body = b''.join(chunks).split(b'\r\n\r\n', 1)
    require(head.startswith(b'HTTP/1.1 200 OK\r\n') and
            b'Content-Type: application/json\r\n' in head + b'\r\n' and
            b'Cache-Control: no-store\r\n' in head + b'\r\n',
            'public response headers')
    length = [line.split(b': ', 1)[1] for line in head.split(b'\r\n')
              if line.startswith(b'Content-Length: ')]
    require(len(length) == 1 and length[0].isdigit() and
            len(body) == int(length[0]), 'public response length')
    return json.loads(body)


def core_fetch(binary, port, base, root_der, now):
    destination = f'127.0.0.1:{port}'
    request = {'expected_did': base['expected_did'],
               'allowed_origins': [ORIGIN], 'destination': destination,
               'allowed_destinations': [destination],
               'root_der': encode(root_der), 'now': now}
    result = subprocess.run([str(binary)], input=json.dumps(request), text=True,
                            capture_output=True, check=True, timeout=20)
    require(not result.stderr, 'core public fetch diagnostic output')
    return json.loads(result.stdout)


def run_case_pair(binaries, journal, row, base, certs, cert_der, key_der):
    if row['write'] != 'none':
        admin_row = {'id': 'controller-create', 'mode': 'controller-create',
                     'client': 'client', 'actor': 'operator',
                     'source': ORIGIN, 'now': 100}
        created = run_case(binaries['admin'], base, admin_row, certs, journal)
        require(created == {'verdict': 'TRANSITION_ACCEPT', 'committed': True},
                'administrator creation was not committed')
        if row['write'] == 'activate':
            admin_row.update(id='controller-activate', mode='controller-activate')
            active = run_case(binaries['admin'], base, admin_row, certs, journal)
            require(active == {'verdict': 'TRANSITION_ACCEPT', 'committed': True},
                    'administrator activation was not committed')
    config = publisher_config(journal, row, base, cert_der, key_der)
    process, port = start_publisher(binaries['publisher'], config)
    if process is None:
        return 'RECORD_UNREACHABLE', None
    try:
        value = python_fetch(port, certs['ca_pem'])
        finish_publisher(process)
        require(value['record']['id'] == base['expected_did'] and
                value['record']['version'] == row['expected_version'] and
                value['issued'] == row['now'] and
                value['expires'] == row['now'] + 5,
                'published body differs from the committed journal')
        process, port = start_publisher(binaries['publisher'], config)
        require(process is not None, 'journal vanished before core fetch')
        verdict = core_fetch(binaries['fetcher'], port, base,
                             certs['root_der'], row['now'])
        finish_publisher(process)
        require(set(verdict) == {'verdict'}, 'core fetch result shape')
        return verdict['verdict'], value['record']['version']
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 shared journal fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-shared-local-journal-publication-vectors' and
            suite['rule_id'] == 'REG-08' and suite['protocol_version'] == '0.10.0' and
            [row['id'] for row in suite['cases']] == list(EXPECTED),
            'shared journal suite identity')
    for row in suite['cases']:
        require(set(row) == {'id', 'write', 'publisher_source', 'publisher_did',
                             'now', 'expected_version', 'expected'} and
                row['expected'] == EXPECTED[row['id']] and
                row['write'] in {'create', 'activate', 'none'} and
                row['publisher_source'] in {ORIGIN, 'other-origin'} and
                row['publisher_did'] in {'expected', 'other'} and
                type(row['now']) is int,
                'shared journal case fields')
    proof = (root / PROOFS).read_bytes()
    require(sha(proof) == PROOFS_SHA256, 'proof fixture changed')
    base = json.loads(proof)['base']
    lock = root / RUST_LOCK
    require(sha(lock.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-public-journal-') as temporary:
        directory = Path(temporary)
        certs = certificates(directory)
        cert_der, key_der = public_certificate_der(directory)
        binaries = build(go_root, rust_root, directory, lock)
        subjects = {}
        for name, programs in binaries.items():
            cases = []
            for row in suite['cases']:
                journal = directory / f'{name}-{row["id"]}.journal'
                actual, version = run_case_pair(programs, journal, row, base,
                                                 certs, cert_der, key_der)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'record_version': version,
                              'match': actual == row['expected']})
            subjects[name] = {'source_revision': revisions[name],
                              'matched': sum(item['match'] for item in cases),
                              'total': len(cases), 'cases': cases,
                              'executables_sha256': {
                                  role: sha(binary.read_bytes())
                                  for role, binary in programs.items()}}
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core shared journal publication mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-local-shared-journal-publication',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'local_shared_journal_publication': 'BOUNDED',
        'deployed_public_server_storage': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 shared journal observation FAIL: ' + str(error) + '\n')
    print('REG-08 local shared journal: Go 5/5, Rust 5/5; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
