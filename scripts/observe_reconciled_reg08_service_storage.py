"""Observe one local Registry service's authenticated writes and public storage."""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import math

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import revision
from observe_reconciled_reg08_admin_mtls import certificates, read_line
from observe_reconciled_reg08_public_binding import public_certificate
from observe_reconciled_reg08_public_journal import core_fetch
from observe_reconciled_reg08_transition_shape import (
    PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)

VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-service-storage.json'
VECTOR_SHA256 = 'c4921d705047beed2454c0ba89a10be157643b3a1d84112576b07b9f5660178d'
SERVICE_REVISION = '431ad432bd5658f7b4911414426cb6fa4374f52e'
GO_REVISION = '8038e1906f9b7595a0589584fdc707fd3f9e2ce1'
RUST_REVISION = '6f16f85c334297ce348c395edd5d6c9462c1d3e8'
ORIGIN = 'https://agents.example.com'
EXPECTED = {
    'empty-record-unavailable': 'UNAVAILABLE',
    'controller-create-published': 'VERSION_1',
    'controller-activate-published': 'VERSION_2',
    'stale-write-preserves-record': 'VERSION_2',
    'malformed-write-preserves-record': 'VERSION_2',
    'restart-preserves-record': 'VERSION_2',
}


def check_vector(root):
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'service storage vector changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'cases'} and suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-local-service-storage-vectors' and
            suite['protocol_version'] == '0.10.0' and suite['rule_id'] == 'REG-08' and
            [row['id'] for row in suite['cases']] == list(EXPECTED),
            'service storage vector identity')
    for row in suite['cases']:
        require(set(row) == {'id', 'expected'} and
                row['expected'] == EXPECTED[row['id']],
                'service storage vector case')
    return suite


def build(service_root, go_root, rust_root, output, lock_source):
    env = os.environ.copy()
    env['GOCACHE'] = str(output / 'go-cache')
    service = output / 'sage-registry-service'
    go_fetcher = output / 'go-fetcher'
    subprocess.run(['go', 'build', '-o', str(service),
                    './cmd/sage-registry-service'], cwd=service_root,
                   env=env, check=True, timeout=300)
    subprocess.run(['go', 'build', '-o', str(go_fetcher),
                    './examples/registry-web-http-record010'], cwd=go_root,
                   env=env, check=True, timeout=300)
    lock = rust_root / 'Cargo.lock'
    if lock.exists():
        require(sha(lock.read_bytes()) == RUST_LOCK_SHA256,
                'Rust dependency lock differs from pinned resolution')
    else:
        shutil.copyfile(lock_source, lock)
    target = Path(os.environ.get('SAGE_REG08_RUST_TARGET', str(output / 'rust-target')))
    subprocess.run(['cargo', 'build', '--locked', '--target-dir', str(target),
                    '--example', 'registry_web_http_record010'],
                   cwd=rust_root, check=True, timeout=600)
    return {'service': service, 'go': go_fetcher,
            'rust': target / 'debug' / 'examples' / 'registry_web_http_record010'}


def configuration(directory, certs, public_cert, public_key, base, create):
    return {
        'public_listen': '127.0.0.1:0', 'admin_listen': '127.0.0.1:0',
        'public_cert_file': str(public_cert), 'public_key_file': str(public_key),
        'admin_cert_file': str(directory / 'server.pem'),
        'admin_key_file': str(directory / 'server.key'),
        'client_ca_file': str(certs['ca_pem']),
        'client_actors': {certs['client_pin']: 'operator'},
        'journal_path': str(directory / 'service.journal'),
        'did': base['expected_did'], 'source': ORIGIN,
        'admin_host': 'admin.example.com', 'create': create,
    }


def start(binary, config_path, config):
    config_path.write_text(json.dumps(config))
    process = subprocess.Popen([str(binary), str(config_path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        first = read_line(process.stdout)
        if not first.strip():
            detail = process.stderr.read()[:200] if process.poll() is not None else ''
            raise ValueError('service emitted no readiness line: ' + detail)
        ready = json.loads(first)
        require(set(ready) == {'public_addr', 'admin_addr'} and
                all(address.startswith('127.0.0.1:') and
                    address.rsplit(':', 1)[1].isdigit()
                    for address in ready.values()) and
                process.poll() is None, 'service did not bind both TLS listeners')
        return process, ready
    except Exception:
        process.kill()
        process.wait(timeout=5)
        raise


def stop(process):
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=15)
    stderr = process.stderr.read()
    require(process.returncode == 0 and stderr == '',
            'service did not close its journal cleanly')


def exchange(address, host, ca, method, path, body=b'', client=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(ca))
    if client is not None:
        context.load_cert_chain(str(client[0]), str(client[1]))
    headers = (f'{method} {path} HTTP/1.1\r\nHost: {host}\r\n'
               'Connection: close\r\n')
    if method == 'POST':
        headers += f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'
    request = headers.encode() + b'\r\n' + body
    port = int(address.rsplit(':', 1)[1])
    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(10)
            tls.sendall(request)
            chunks = []
            size = 0
            while True:
                part = tls.recv(8192)
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                require(size <= 90_000, 'service response exceeds bound')
    head, content = b''.join(chunks).split(b'\r\n\r\n', 1)
    status = int(head.split(b'\r\n', 1)[0].split(b' ')[1])
    lengths = [line.split(b':', 1)[1].strip() for line in head.split(b'\r\n')
               if line.lower().startswith(b'content-length:')]
    require(len(lengths) <= 1 and (not lengths or
            lengths[0].isdigit() and len(content) == int(lengths[0])),
            'ambiguous service response length')
    return status, head, content


def candidate(base, state, version, now):
    record = copy.deepcopy(base['body']['record'])
    record.update(state=state, version=version)
    return json.dumps({'record': record, 'issued': now, 'expires': now + 5},
                      separators=(',', ':')).encode()


def write(ready, certs, base, state, version, expected, operation):
    now = int(time.time())
    encoded = base64.urlsafe_b64encode(candidate(base, state, version, now)).rstrip(b'=').decode()
    request = json.dumps({'candidate': encoded, 'expected_version': expected,
                          'operation': operation}, separators=(',', ':')).encode()
    return exchange(ready['admin_addr'], 'admin.example.com', certs['ca_pem'],
                    'POST', '/admin/registry', request,
                    (certs['client_cert'], certs['client_key']))[0]


def public(ready, certs, version):
    status, head, body = exchange(ready['public_addr'], 'agents.example.com',
                                  certs['ca_pem'], 'GET',
                                  '/.well-known/sage/agents/billing-bot')
    require(status == 200 and b'Content-Type: application/json\r\n' in head + b'\r\n'
            and b'Cache-Control: no-store\r\n' in head + b'\r\n',
            'public media or cache policy')
    value = json.loads(body)
    now = int(time.time())
    require(value['record']['version'] == version and
            value['record']['id'] == 'did:sage:web:agents.example.com:billing-bot' and
            value['issued'] <= now < value['expires'] and
            value['expires'] - value['issued'] == 5,
            'public response differs from the committed state')
    return value


def observe(service_root, go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    suite = check_vector(root)
    proof = (root / PROOFS).read_bytes()
    require(sha(proof) == PROOFS_SHA256, 'proof fixture changed')
    base = json.loads(proof)['base']
    lock = root / RUST_LOCK
    require(sha(lock.read_bytes()) == RUST_LOCK_SHA256,
            'Rust dependency lock fixture changed')
    revisions = {'service': revision(service_root), 'go': revision(go_root),
                 'rust': revision(rust_root)}
    require(revisions == {'service': SERVICE_REVISION, 'go': GO_REVISION,
                          'rust': RUST_REVISION}, 'source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-service-storage-') as tmp:
        directory = Path(tmp)
        certs = certificates(directory)
        public_cert, public_key = public_certificate(directory, 'public',
                                                      'agents.example.com')
        binaries = build(service_root, go_root, rust_root, directory, lock)
        config_path = directory / 'service.json'
        process, ready = start(binaries['service'], config_path,
                               configuration(directory, certs, public_cert,
                                             public_key, base, True))
        cases = []
        fetch_attempts = {}

        def record(case, actual):
            cases.append({'id': case, 'expected': EXPECTED[case],
                          'actual': actual, 'match': actual == EXPECTED[case]})

        try:
            status, _, _ = exchange(ready['public_addr'], 'agents.example.com',
                                    certs['ca_pem'], 'GET',
                                    '/.well-known/sage/agents/billing-bot')
            record('empty-record-unavailable', 'UNAVAILABLE' if status == 503 else str(status))
            require(write(ready, certs, base, 'created', '1', '', 'create') == 204,
                    'controller creation failed')
            public(ready, certs, '1')
            record('controller-create-published', 'VERSION_1')
            require(write(ready, certs, base, 'active', '2', '1', 'activate') == 204,
                    'controller activation failed')
            public(ready, certs, '2')
            for role in ('go', 'rust'):
                port = ready['public_addr'].rsplit(':', 1)[1]
                attempts = []
                for attempt in range(2):
                    sampled_now = int(time.time())
                    verdict = core_fetch(binaries[role], port, base,
                                         certs['root_der'], sampled_now)
                    attempts.append({'sampled_now': sampled_now,
                                     'verdict': verdict['verdict']})
                    if verdict == {'verdict': 'RECORD_ACCEPT'}:
                        break
                    require(attempt == 0 and verdict == {'verdict': 'RECORD_INVALID'},
                            role + ' core rejected the service record: ' + str(verdict))
                    next_second = math.floor(time.time()) + 1.05
                    time.sleep(max(0, next_second - time.time()))
                require(verdict == {'verdict': 'RECORD_ACCEPT'},
                        role + ' core rejected the service record: ' + str(verdict))
                fetch_attempts[role] = attempts
            record('controller-activate-published', 'VERSION_2')
            require(write(ready, certs, base, 'deactivated', '3', '1', 'deactivate') == 409,
                    'stale write was accepted')
            public(ready, certs, '2')
            record('stale-write-preserves-record', 'VERSION_2')
            malformed = b'{"candidate":"a","candidate":"b","expected_version":"2","operation":"deactivate"}'
            status, _, _ = exchange(ready['admin_addr'], 'admin.example.com',
                                     certs['ca_pem'], 'POST', '/admin/registry', malformed,
                                     (certs['client_cert'], certs['client_key']))
            require(status == 400, 'duplicate administrator field was accepted')
            public(ready, certs, '2')
            record('malformed-write-preserves-record', 'VERSION_2')
            stop(process)
            process, ready = start(binaries['service'], config_path,
                                   configuration(directory, certs, public_cert,
                                                 public_key, base, False))
            public(ready, certs, '2')
            record('restart-preserves-record', 'VERSION_2')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        require([row['id'] for row in cases] == [row['id'] for row in suite['cases']] and
                all(row['match'] for row in cases), 'service storage cases diverged')
        hashes = {name: sha(path.read_bytes()) for name, path in binaries.items()}
    return {
        'schema_version': 1, 'kind': 'reg08-local-service-storage-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'source_revisions': revisions, 'executables_sha256': hashes,
        'core_fetch_attempts': fetch_attempts,
        'cases': cases, 'matched': len(cases), 'total': len(EXPECTED),
        'local_service_storage': 'BOUNDED', 'local_admin_http_framing': 'BOUNDED',
        'deployed_public_server_storage': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN', 'remote_atomic_write': 'NOT_RUN',
        'parent_cases': {name: 'NOT_RUN' for name in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'conformance': 'NOT_ESTABLISHED',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-root', type=Path, required=True)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = observe(args.service_root, args.go_root, args.rust_root,
                         args.spec_root)
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, IndexError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, 'REG-08 service storage observation FAIL: ' + str(error) + '\n')
    print('REG-08 local service storage: 6/6; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
