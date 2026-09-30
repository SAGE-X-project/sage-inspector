"""Observe pinned Go and Rust bounded HTTP reads through local authenticated TLS."""

import argparse
import base64
from contextlib import suppress
import copy
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
from observe_reconciled_reg08_tls_origin import certificate


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-http-record.json'
VECTOR_SHA256 = '27517ce6b52c402657aa3b0d152dbd33db89611bd7cbceeef40388257aa0a827'
PROOFS = 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json'
PROOFS_SHA256 = '06e06202900d168a0faaceca101cc2c915b30ff5de61f0bb40fb7bc19afd91ab'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-tls-origin-Cargo.lock'
RUST_LOCK_SHA256 = '04099b5ee7c1320fb249112b1fba052aad1a433cc26d60e4537db108b69d6a38'
GO_REVISION = '2d6704578648c0c439991eaf86bf6b55af263f8b'
RUST_REVISION = '066f688e30002d867c5f409d73375037123479e4'
EXPECTED = {
    'valid': 'RECORD_ACCEPT',
    'redirect': 'RECORD_UNREACHABLE',
    'wrong-media': 'RECORD_INVALID',
    'missing-no-store': 'RECORD_INVALID',
    'content-encoding': 'RECORD_INVALID',
    'missing-length': 'RECORD_INVALID',
    'duplicate-length': 'RECORD_INVALID',
    'transfer-coding': 'RECORD_INVALID',
    'oversized-length': 'SIZE_EXCEEDED',
    'truncated-body': 'RECORD_UNREACHABLE',
    'changed-proof': 'RECORD_INVALID',
    'wrong-certificate-name': 'RECORD_UNREACHABLE',
    'unapproved-destination': 'RECORD_UNREACHABLE',
}
REQUEST = (b'GET /.well-known/sage/agents/billing-bot HTTP/1.1\r\n'
           b'Host: agents.example.com\r\nAccept: application/json\r\n'
           b'Cache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n')


def response(mode, body):
    if mode == 'changed-proof':
        altered = copy.deepcopy(json.loads(body))
        proof = altered['record']['keys'][0]['proof']
        proof['value'] = ('A' if proof['value'][0] != 'A' else 'B') + proof['value'][1:]
        body = json.dumps(altered, separators=(',', ':')).encode()
    status = '301 Moved Permanently' if mode == 'redirect' else '200 OK'
    fields = [f'HTTP/1.1 {status}',
              'Content-Type: text/plain' if mode == 'wrong-media'
              else 'Content-Type: application/json']
    if mode != 'missing-no-store':
        fields.append('Cache-Control: no-store')
    if mode == 'content-encoding':
        fields.append('Content-Encoding: identity')
    if mode != 'missing-length':
        size = 69633 if mode == 'oversized-length' else len(body)
        fields.append(f'Content-Length: {size}')
    if mode == 'duplicate-length':
        fields.append(f'Content-Length: {len(body)}')
    if mode == 'transfer-coding':
        fields.append('Transfer-Encoding: chunked')
    if mode == 'truncated-body':
        body = body[:-1]
    return ('\r\n'.join(fields) + '\r\n\r\n').encode() + body


class LocalHTTPRegistry:
    def __init__(self, cert, key, content):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.context = context
        self.content = content
        self.request = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(4)
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
                    with self.context.wrap_socket(connection, server_side=True) as tls:
                        request = bytearray()
                        while not request.endswith(b'\r\n\r\n') and len(request) < 4096:
                            chunk = tls.recv(4096 - len(request))
                            if not chunk:
                                break
                            request.extend(chunk)
                        self.request = bytes(request)
                        if self.request == REQUEST:
                            tls.sendall(self.content)

    def stop(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=2)


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-http-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-http-record010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_http_record010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_web_http_record010'
    require(go_binary.is_file() and rust_binary.is_file(), 'HTTP adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, row, body, certs):
    mode = row['mode']
    cert = certs['other' if mode == 'wrong-certificate-name' else 'valid']
    server = LocalHTTPRegistry(cert[0], cert[1], response(mode, body)).start()
    try:
        request = {
            'expected_did': 'did:sage:web:agents.example.com:billing-bot',
            'allowed_origins': ['https://agents.example.com'],
            'destination': server.endpoint,
            'allowed_destinations': [] if mode == 'unapproved-destination'
            else [server.endpoint],
            'root_der': base64.urlsafe_b64encode(cert[2]).rstrip(b'=').decode(),
            'now': 100,
        }
        process = subprocess.run([str(binary)], input=json.dumps(request),
                                 text=True, capture_output=True, timeout=10,
                                 check=False)
        require(process.returncode == 0 and not process.stderr and
                len(process.stdout) <= 256, 'HTTP adapter failed: ' + row['id'])
        result = json.loads(process.stdout)
        require(type(result) is dict and set(result) == {'verdict'} and
                result['verdict'] in set(EXPECTED.values()),
                'HTTP adapter verdict: ' + row['id'])
        expected_request = None if mode in {
            'wrong-certificate-name', 'unapproved-destination'} else REQUEST
        require(server.request == expected_request,
                'HTTP request did not use the expected TLS path: ' + row['id'])
        return result['verdict']
    finally:
        server.stop()


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 HTTP fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-http-record-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'HTTP suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == EXPECTED[row['mode']], 'HTTP case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'HTTP case set')
    proof_raw = (root / PROOFS).read_bytes()
    require(sha(proof_raw) == PROOFS_SHA256, 'proof fixture changed')
    proof_base = json.loads(proof_raw)['base']
    body = json.dumps(proof_base['body'], separators=(',', ':')).encode()
    require(proof_base['now'] == 100 and len(body) <= 69632,
            'proof fixture timestamp or size')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-http-') as temporary:
        output = Path(temporary)
        binaries = build(go_root, rust_root, output, lock_source)
        certs = {
            'valid': certificate(output, 'valid', 'agents.example.com'),
            'other': certificate(output, 'other', 'other.example.com'),
        }
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, row, body, certs)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core HTTP record mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-http-record-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'authenticated_http_record': 'BOUNDED_CONTENT_LENGTH',
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
        parser.exit(1, 'REG-08 core HTTP observation FAIL: ' + str(error) + '\n')
    print('REG-08 HTTP record: Go 13/13, Rust 13/13; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
