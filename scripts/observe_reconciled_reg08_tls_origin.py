"""Observe pinned Go and Rust web Registry TLS-origin subconditions."""

import argparse
import base64
from contextlib import suppress
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


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-tls-origin.json'
VECTOR_SHA256 = 'f9598ce9e3f3058e00fd18e3d13eafabb09815a655c5b6594ca94ff771daaa2a'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-tls-origin-Cargo.lock'
RUST_LOCK_SHA256 = '04099b5ee7c1320fb249112b1fba052aad1a433cc26d60e4537db108b69d6a38'
GO_REVISION = 'bb75ff3111dcaa6dc4981cb53dc1cb922578c75c'
RUST_REVISION = 'b4cb29884b315c80f6cf83dae5aaff8e642e818d'
EXPECTED = {
    'approved-origin-and-certificate': 'TLS_ACCEPT',
    'unapproved-origin': 'RECORD_UNREACHABLE',
    'unapproved-destination': 'RECORD_UNREACHABLE',
    'unknown-certificate-root': 'RECORD_UNREACHABLE',
    'certificate-for-other-name': 'RECORD_UNREACHABLE',
    'malformed-root': 'RECORD_UNREACHABLE',
    'invalid-ip-literal-did': 'RECORD_INVALID',
    'different-did-domain': 'RECORD_UNREACHABLE',
    'zero-port-destination': 'RECORD_UNREACHABLE',
}


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], capture_output=True,
                   check=True, timeout=20)


def certificate(directory, label, hostname):
    folder = directory / label
    folder.mkdir()
    ca_key, ca_pem = folder / 'ca.key', folder / 'ca.pem'
    key, csr, cert = folder / 'server.key', folder / 'server.csr', folder / 'server.pem'
    extensions = folder / 'server.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\n'
                          f'subjectAltName=DNS:{hostname}\n')
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
            '-subj', f'/CN=SAGE local {label} CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', ca_key, '-out', ca_pem)
    openssl('req', '-new', '-newkey', 'rsa:2048', '-noenc',
            '-subj', f'/CN={hostname}', '-keyout', key, '-out', csr)
    openssl('x509', '-req', '-in', csr, '-CA', ca_pem, '-CAkey', ca_key,
            '-CAcreateserial', '-days', '1', '-out', cert, '-extfile', extensions)
    return cert, key, ssl.PEM_cert_to_DER_cert(ca_pem.read_text())


class LocalTLSServer:
    def __init__(self, cert, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.context = context
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.endpoint = f'127.0.0.1:{self.socket.getsockname()[1]}'
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def serve(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(5)
                with suppress(ssl.SSLError, OSError):
                    with self.context.wrap_socket(connection, server_side=True):
                        pass

    def stop(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=2)


def payload(base, row, servers, roots):
    require(set(row) == {'id', 'server', 'expected', 'overrides'} and
            row['server'] in servers and type(row['overrides']) is dict and
            set(row['overrides']) <= set(base), 'TLS case fields')
    request = {**base, **row['overrides']}
    endpoint = servers[row['server']].endpoint
    request['destination'] = (endpoint if request['destination'] == '@server'
                              else request['destination'])
    request['allowed_destinations'] = [
        endpoint if entry == '@server' else entry
        for entry in request['allowed_destinations']
    ]
    root = request['root_der']
    root_bytes = (roots[row['server']] if root == '@server' else
                  roots['other'] if root == '@other' else
                  b'\x01' if root == '@invalid' else None)
    require(root_bytes is not None, 'TLS root selector')
    request['root_der'] = base64.urlsafe_b64encode(root_bytes).rstrip(b'=').decode()
    encoded = json.dumps(request, separators=(',', ':'))
    require(len(encoded.encode()) <= 16384, 'TLS request bound')
    return encoded


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-tls-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-tls-origin010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_tls_origin010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_web_tls_origin010'
    require(go_binary.is_file() and rust_binary.is_file(), 'TLS adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, base, row, servers, roots):
    process = subprocess.run([str(binary)], input=payload(base, row, servers, roots),
                             text=True, capture_output=True, timeout=10,
                             check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'TLS adapter failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict'} and
            response['verdict'] in set(EXPECTED.values()),
            'TLS adapter verdict: ' + row['id'])
    return response['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Record actual local TLS handshakes without claiming an HTTP record read."""
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 TLS fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'provenance', 'base', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-tls-origin-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == len(EXPECTED), 'TLS suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in EXPECTED and ident not in seen and
                row['expected'] == EXPECTED[ident] and
                row['server'] in {'valid', 'other'}, 'TLS case: ' + ident)
        seen.add(ident)
    require(seen == set(EXPECTED), 'TLS case set')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-tls-') as temporary:
        output = Path(temporary)
        binaries = build(go_root, rust_root, output, lock_source)
        certs = {
            'valid': certificate(output, 'valid', 'agents.example.com'),
            'other': certificate(output, 'other', 'other.example.com'),
        }
        roots = {name: files[2] for name, files in certs.items()}
        servers = {name: LocalTLSServer(files[0], files[1]).start()
                   for name, files in certs.items()}
        try:
            subjects = {}
            for name, binary in binaries.items():
                cases = []
                for row in suite['cases']:
                    actual = run_case(binary, suite['base'], row, servers, roots)
                    cases.append({'id': row['id'], 'expected': row['expected'],
                                  'actual': actual, 'match': actual == row['expected']})
                subjects[name] = {
                    'source_revision': actual_revisions[name],
                    'executable_sha256': sha(binary.read_bytes()),
                    'matched': sum(case['match'] for case in cases),
                    'total': len(cases), 'cases': cases,
                }
        finally:
            for server in servers.values():
                server.stop()
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core TLS origin mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-tls-origin-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'authenticated_http_record': 'NOT_RUN',
        'controller_and_mutation_history': 'NOT_RUN',
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
            subprocess.SubprocessError, json.JSONDecodeError, ssl.SSLError) as error:
        parser.exit(1, 'REG-08 core TLS observation FAIL: ' + str(error) + '\n')
    print('REG-08 TLS origin: Go 9/9, Rust 9/9; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
