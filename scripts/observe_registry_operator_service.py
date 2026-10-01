"""Observe bounded Registry operator transactions through the service mTLS boundary."""

import argparse
import base64
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from current_spec_catalog import ROOT, require, sha
from observe_reconciled_reg08_admin_mtls import certificates, openssl
from observe_reconciled_reg08_public_binding import public_certificate
from observe_reconciled_reg08_record_shape import revision
from observe_reconciled_reg08_service_storage import exchange, start, stop
from observe_reconciled_reg08_transition_shape import PROOFS, PROOFS_SHA256


VECTOR = 'vectors/0.10.0/registry-operator/subconditions.json'
VECTOR_SHA256 = 'c79ecaa507b8d92e2847924f1e4a19330ecfc2749372bfaa99d5503fd023046b'
SPEC_REVISION = 'fa006fd917ad365eb554a27f4178301cd66e2379'
GO_REVISION = '9c7dce33202377721259d246acd7d973d2dc0d86'
SERVICE_REVISION = 'baf5570578ddc19685ebe2a5bda4a284f45c8e05'
ORIGIN = 'https://agents.example.com'
DID = 'did:sage:web:agents.example.com:billing-bot'
PUBLIC_PATH = '/.well-known/sage/agents/billing-bot'
LOCAL_CASES = {
    'controller-grant', 'exact-scope-write', 'controller-revoke',
    'state-retirement', 'explicit-regrant', 'duplicate-or-missing-grant',
    'stale-version', 'competing-commands', 'restart-history',
    'deactivated-management', 'operator-delegates',
    'scope-or-identity-mismatch', 'public-read-atomicity',
    'expired-key-management', 'grant-capacity', 'uncertain-commit',
}
PENDING_CASES = {
    'storage-authority-loss': 'No deployed origin and storage owner were supplied.',
}


def check_vector(root=ROOT):
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'operator vector changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version', 'scope', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'registry-operator-transaction-subconditions' and
            suite['protocol_version'] == '0.10.0' and len(suite['cases']) == 17,
            'operator vector identity')
    ids = [row['id'] for row in suite['cases']]
    require(len(set(ids)) == 17 and set(ids) == LOCAL_CASES | set(PENDING_CASES),
            'operator vector case set')
    for row in suite['cases']:
        require(set(row) == {'id', 'parent_case_id', 'precondition', 'expected',
                             'evidence_status'} and
                row['parent_case_id'] in {'REG-03-P', 'REG-03-N01', 'REG-03-N02',
                                          'REG-03-N03', 'REG-03-N04', 'REG-08-P',
                                          'REG-08-N03'} and
                row['evidence_status'] == 'planned_not_executed' and
                all(type(row[field]) is str and row[field]
                    for field in ('id', 'precondition', 'expected')),
                'operator vector case shape')
    return suite


def check_report(report, root=ROOT):
    suite = check_vector(root)
    require(set(report) == {'schema_version', 'kind', 'protocol_version',
                            'spec_revision', 'vector_sha256', 'subject_revisions',
                            'service_executable_sha256', 'cases', 'local_pass',
                            'partial', 'not_run', 'deployed_reg08', 'conformance'} and
            report['schema_version'] == 1 and
            report['kind'] == 'registry-operator-local-observation' and
            report['protocol_version'] == '0.10.0' and
            report['spec_revision'] == SPEC_REVISION and
            report['vector_sha256'] == VECTOR_SHA256 and
            report['subject_revisions'] == {'service': SERVICE_REVISION,
                                            'go': GO_REVISION,
                                            'spec': SPEC_REVISION} and
            len(report['service_executable_sha256']) == 64 and
            all(ch in '0123456789abcdef'
                for ch in report['service_executable_sha256']) and
            report['local_pass'] == 15 and report['partial'] == 1 and
            report['not_run'] == 1 and report['deployed_reg08'] == 'NOT_RUN' and
            report['conformance'] == 'NOT_ESTABLISHED',
            'operator report identity or verdict promotion')
    require([row['id'] for row in report['cases']] ==
            [row['id'] for row in suite['cases']], 'operator report case order')
    for row, planned in zip(report['cases'], suite['cases']):
        require(row['parent_case_id'] == planned['parent_case_id'] and
                row['track'] == 'local_tls_runtime',
                'operator report parent or track mismatch')
        if row['id'] == 'storage-authority-loss':
            require(row['status'] == 'NOT_RUN' and row['reason'] ==
                    PENDING_CASES[row['id']], 'deployed storage was promoted')
        elif row['id'] == 'expired-key-management':
            require(row['status'] == 'PARTIAL' and row['reason'] ==
                    'Expired signing keys and management were observed; '
                    'no protected-message authorization was exercised.',
                    'expired-key observation was overclaimed')
        else:
            require(set(row) == {'id', 'parent_case_id', 'status', 'track'} and
                    row['status'] == 'PASS', 'local operator observation missing')
    return True


def issue_inspector(directory):
    cert, key, csr = (directory / 'inspector.pem', directory / 'inspector.key',
                      directory / 'inspector.csr')
    ext = directory / 'inspector.ext'
    ext.write_text('basicConstraints=critical,CA:FALSE\n'
                   'keyUsage=critical,digitalSignature\n'
                   'extendedKeyUsage=clientAuth\n'
                   'subjectAltName=DNS:inspector.example.com\n')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-noenc',
            '-subj', '/CN=inspector.example.com', '-keyout', key, '-out', csr)
    openssl('x509', '-req', '-in', csr, '-CA', directory / 'ca.pem',
            '-CAkey', directory / 'ca.key', '-CAcreateserial', '-days', '1',
            '-out', cert, '-extfile', ext)
    der = directory / 'inspector.der'
    openssl('x509', '-in', cert, '-outform', 'DER', '-out', der)
    return cert, key, hashlib.sha256(der.read_bytes()).hexdigest()


def cert_pin(cert, directory):
    der = directory / 'operator.der'
    openssl('x509', '-in', cert, '-outform', 'DER', '-out', der)
    return hashlib.sha256(der.read_bytes()).hexdigest()


def configuration(directory, certs, public_cert, public_key, inspector, create):
    return {
        'public_listen': '127.0.0.1:0', 'admin_listen': '127.0.0.1:0',
        'public_cert_file': str(public_cert), 'public_key_file': str(public_key),
        'admin_cert_file': str(directory / 'server.pem'),
        'admin_key_file': str(directory / 'server.key'),
        'client_ca_file': str(certs['ca_pem']),
        'client_actors': {certs['client_pin']: 'operator',
                          cert_pin(certs['other_cert'], directory): 'delegate'},
        'inspector_clients': [inspector[2]],
        'journal_path': str(directory / 'service.journal'),
        'did': DID, 'source': ORIGIN, 'admin_host': 'admin.example.com',
        'create': create,
    }


def command(operation, expected, *, candidate=None, target=None, scope=None,
            registry=ORIGIN, did=DID):
    value = {'registry': registry, 'did': did, 'operation': operation,
             'expected_version': expected}
    if candidate is not None:
        value['candidate'] = base64.urlsafe_b64encode(candidate).rstrip(b'=').decode()
    if target is not None:
        value['target_operator'] = target
    if scope is not None:
        value['scope'] = scope
    return json.dumps(value, separators=(',', ':')).encode()


def candidate(record, state, version):
    body = copy.deepcopy(record)
    body.update(state=state, version=str(version))
    now = int(time.time())
    return json.dumps({'record': body, 'issued': now, 'expires': now + 5},
                      separators=(',', ':')).encode()


def submit(ready, certs, body, identity):
    return exchange(ready['admin_addr'], 'admin.example.com', certs['ca_pem'],
                    'POST', '/admin/registry', body, identity)[0]


def inspect(ready, certs, inspector):
    status, _, raw = exchange(ready['admin_addr'], 'admin.example.com',
                              certs['ca_pem'], 'GET',
                              '/admin/registry/inspection', client=inspector[:2])
    require(status == 200, 'authenticated inspection unavailable')
    result = json.loads(raw)
    require(set(result) == {'registry', 'did', 'version', 'grants',
                            'history', 'tombstoned'} and
            result['registry'] == ORIGIN and result['did'] == DID and
            type(result['version']) is str and result['version'].isdigit() and
            len(result['history']) == int(result['version']) and
            type(result['grants']) is list and
            type(result['tombstoned']) is bool,
            'incomplete committed inspection state')
    return result


def public(ready, certs):
    status, head, raw = exchange(ready['public_addr'], 'agents.example.com',
                                  certs['ca_pem'], 'GET', PUBLIC_PATH)
    require(status == 200 and b'Cache-Control: no-store\r\n' in head + b'\r\n',
            'public response unavailable or cacheable')
    result = json.loads(raw)
    require(set(result) == {'record', 'issued', 'expires'} and
            result['record']['id'] == DID and
            result['issued'] <= int(time.time()) < result['expires'] and
            result['expires'] - result['issued'] == 5,
            'public response is not a fresh complete record')
    return result


def observe_capacity(binary, directory, config_path, config, certs, controller,
                     record):
    capacity_config = copy.deepcopy(config)
    capacity_config['journal_path'] = str(directory / 'capacity.journal')
    capacity_config['create'] = True
    for number in range(1, 130):
        pin = hashlib.sha256(f'capacity-{number}'.encode()).hexdigest()
        capacity_config['client_actors'][pin] = f'capacity-{number}'
    process, ready = start(binary, config_path, capacity_config)
    try:
        require(submit(ready, certs,
                       command('create', '', candidate=candidate(record, 'created', 1)),
                       controller) == 204, 'capacity record creation failed')
        for number in range(1, 129):
            status = submit(ready, certs,
                            command('authorize-operator', str(number),
                                    target=f'capacity-{number}', scope='activate'),
                            controller)
            require(status == 204, f'grant {number} rejected before capacity')
        before = public(ready, certs)
        status = submit(ready, certs,
                        command('authorize-operator', '129',
                                target='capacity-129', scope='activate'), controller)
        after = public(ready, certs)
        return (status == 403 and before['record']['version'] == '129' and
                after['record'] == before['record'])
    finally:
        stop(process)


def observe_expired_management(binary, directory, config_path, config, certs,
                               controller, inspector, record):
    expired_config = copy.deepcopy(config)
    expired_config['journal_path'] = str(directory / 'expired.journal')
    expired_config['create'] = True
    trimmed = copy.deepcopy(record)
    trimmed['keys'] = trimmed['keys'][:2]
    expiry = int(time.time()) + 8
    trimmed['keys'][0]['expires'] = expiry
    process, ready = start(binary, config_path, expired_config)
    try:
        require(submit(ready, certs,
                       command('create', '', candidate=candidate(trimmed, 'created', 1)),
                       controller) == 204, 'expiring record creation failed')
        require(submit(ready, certs,
                       command('activate', '1',
                               candidate=candidate(trimmed, 'active', 2)),
                       controller) == 204, 'expiring record activation failed')
        require(submit(ready, certs,
                       command('authorize-operator', '2', target='delegate',
                               scope='add-key'), controller) == 204,
                'pre-expiry grant failed')
        time.sleep(max(0, expiry + 1 - time.time()))
        before = public(ready, certs)
        require(before['record']['state'] == 'active' and
                all(key['expires'] <= int(time.time())
                    for key in before['record']['keys']
                    if key['alg'] != 'x25519' and key['state'] == 'accepted'),
                'signing keys did not expire')
        status = submit(ready, certs,
                        command('revoke-operator', '3', target='delegate',
                                scope='add-key'), controller)
        after = inspect(ready, certs, inspector)
        current = public(ready, certs)
        require(status == 204 and after['version'] == '4' and
                after['grants'] == [] and current['record']['state'] == 'active',
                f'expired management status={status}, version={after["version"]}, '
                f'grants={after["grants"]}, state={current["record"]["state"]}')
        return True
    finally:
        stop(process)


def observe_uncertain_restart(binary, directory, config_path, config):
    uncertain_config = copy.deepcopy(config)
    source = Path(config['journal_path'])
    target = directory / 'uncertain.journal'
    shutil.copyfile(source, target)
    with target.open('ab') as journal:
        journal.write(b'{"incomplete":')
    uncertain_config['journal_path'] = str(target)
    uncertain_config['create'] = False
    config_path.write_text(json.dumps(uncertain_config))
    process = subprocess.run([str(binary), str(config_path)], capture_output=True,
                             text=True, timeout=15)
    return process.returncode != 0 and not process.stdout.strip()


def observe(service_root, go_root, spec_root, root=ROOT):
    suite = check_vector(root)
    revisions = {'service': revision(service_root), 'go': revision(go_root),
                 'spec': revision(spec_root)}
    require(revisions == {'service': SERVICE_REVISION, 'go': GO_REVISION,
                          'spec': SPEC_REVISION}, 'operator subject revision mismatch')
    require(sha((root / PROOFS).read_bytes()) == PROOFS_SHA256,
            'proof fixture changed')
    base = json.loads((root / PROOFS).read_bytes())['base']
    record = base['body']['record']
    require(record['controller'] == 'operator' and record['id'] == DID,
            'proof fixture identity changed')
    observed = {}

    def passed(name, condition):
        require(name in LOCAL_CASES and condition, 'operator case failed: ' + name)
        observed[name] = {'status': 'PASS', 'track': 'local_tls_runtime'}

    with tempfile.TemporaryDirectory(prefix='sage-operator-inspection-') as tmp:
        directory = Path(tmp)
        certs = certificates(directory)
        inspector = issue_inspector(directory)
        public_cert, public_key = public_certificate(directory, 'public',
                                                      'agents.example.com')
        binary = directory / 'sage-registry-service'
        environment = os.environ.copy()
        environment['GOCACHE'] = str(directory / 'go-cache')
        subprocess.run(['go', 'build', '-o', str(binary),
                        './cmd/sage-registry-service'], cwd=service_root,
                       env=environment, check=True, timeout=300)
        config_path = directory / 'service.json'
        config = configuration(directory, certs, public_cert, public_key,
                               inspector, True)
        process, ready = start(binary, config_path, config)
        controller = (certs['client_cert'], certs['client_key'])
        delegate = (certs['other_cert'], certs['other_key'])
        try:
            require(submit(ready, certs,
                           command('create', '', candidate=candidate(record, 'created', 1)),
                           controller) == 204, 'controller create failed')
            grant = lambda expected, scope: command('authorize-operator', expected,
                                                       target='delegate', scope=scope)
            revoke = lambda expected, scope: command('revoke-operator', expected,
                                                       target='delegate', scope=scope)
            require(submit(ready, certs, grant('1', 'activate'), controller) == 204,
                    'controller grant failed')
            state = inspect(ready, certs, inspector)
            passed('controller-grant', state['version'] == '2' and
                   state['grants'] == [{'operator': 'delegate', 'scope': 'activate'}] and
                   state['history'][-1]['operation'] == 'authorize-operator' and
                   public(ready, certs)['record']['version'] == '2')

            duplicate = submit(ready, certs, grant('2', 'activate'), controller)
            missing = submit(ready, certs, revoke('2', 'deactivate'), controller)
            passed('duplicate-or-missing-grant', duplicate == 403 and missing == 403 and
                   inspect(ready, certs, inspector) == state)

            delegation = submit(ready, certs, grant('2', 'deactivate'), delegate)
            operator_revoke = submit(ready, certs, revoke('2', 'activate'), delegate)
            passed('operator-delegates', delegation == 403 and operator_revoke == 403 and
                   inspect(ready, certs, inspector) == state)

            wrong_scope = submit(ready, certs,
                                 command('deactivate', '2',
                                         candidate=candidate(record, 'deactivated', 3)),
                                 delegate)
            wrong_registry = submit(ready, certs,
                                    command('authorize-operator', '2', target='delegate',
                                            scope='deactivate',
                                            registry='https://other.example.com'), controller)
            wrong_did = submit(ready, certs,
                               command('authorize-operator', '2', target='delegate',
                                       scope='deactivate', did=DID + '-other'), controller)
            unbound_target = submit(ready, certs,
                                    command('authorize-operator', '2', target='unbound',
                                            scope='deactivate'), controller)
            inspector_write = submit(ready, certs, grant('2', 'deactivate'), inspector[:2])
            passed('scope-or-identity-mismatch',
                   (wrong_scope, wrong_registry, wrong_did, unbound_target,
                    inspector_write) == (403, 400, 400, 403, 403) and
                   inspect(ready, certs, inspector) == state)

            stale = [submit(ready, certs, grant(value, 'deactivate'), controller)
                     for value in ('1', '', '02', str(2**64-1))]
            passed('stale-version', stale == [409] * 4 and
                   inspect(ready, certs, inspector) == state)

            require(submit(ready, certs,
                           command('activate', '2',
                                   candidate=candidate(record, 'active', 3)),
                           delegate) == 204, 'delegated activation failed')
            state = inspect(ready, certs, inspector)
            passed('exact-scope-write', state['version'] == '3' and
                   state['history'][-1]['actor'] == 'delegate' and
                   public(ready, certs)['record']['state'] == 'active')
            passed('state-retirement', state['grants'] == [])

            require(submit(ready, certs, grant('3', 'update-services'), controller) == 204 and
                    submit(ready, certs, grant('4', 'add-key'), controller) == 204,
                    'active grants failed')
            require(submit(ready, certs, revoke('5', 'update-services'), controller) == 204,
                    'controller revoke failed')
            state = inspect(ready, certs, inspector)
            passed('controller-revoke', state['version'] == '6' and
                   state['grants'] == [{'operator': 'delegate', 'scope': 'add-key'}] and
                   state['history'][-1]['target'] == 'delegate' and
                   state['history'][-1]['scope'] == 'update-services')
            require(submit(ready, certs, grant('6', 'update-services'), controller) == 204,
                    'explicit regrant failed')
            state = inspect(ready, certs, inspector)
            passed('explicit-regrant', state['version'] == '7' and
                   state['grants'] == [{'operator': 'delegate', 'scope': 'add-key'},
                                       {'operator': 'delegate', 'scope': 'update-services'}])

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(submit, ready, certs, revoke('7', scope), controller)
                           for scope in ('add-key', 'update-services')]
                outcomes = sorted(future.result(timeout=20) for future in futures)
            state = inspect(ready, certs, inspector)
            passed('competing-commands', outcomes == [204, 409] and
                   state['version'] == '8' and len(state['grants']) == 1)
            before_restart = state
            stop(process)
            config['create'] = False
            process, ready = start(binary, config_path, config)
            state = inspect(ready, certs, inspector)
            passed('restart-history', state == before_restart and
                   public(ready, certs)['record']['version'] == '8')

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                read_future = pool.submit(public, ready, certs)
                write_future = pool.submit(submit, ready, certs,
                                           command('deactivate', '8',
                                                   candidate=candidate(record, 'deactivated', 9)),
                                           controller)
                raced_read = read_future.result(timeout=20)
                write_status = write_future.result(timeout=20)
            final = inspect(ready, certs, inspector)
            passed('public-read-atomicity', write_status == 204 and
                   raced_read['record']['version'] in {'8', '9'} and
                   raced_read['record']['state'] in {'active', 'deactivated'} and
                   (raced_read['record']['version'] == '8') ==
                   (raced_read['record']['state'] == 'active') and
                   final['version'] == '9' and final['grants'] == [])
            rejected = submit(ready, certs, grant('9', 'deactivate'), controller)
            operator_write = submit(ready, certs,
                                    command('deactivate', '9',
                                            candidate=candidate(record, 'deactivated', 10)),
                                    delegate)
            passed('deactivated-management', rejected != 204 and operator_write != 204 and
                   inspect(ready, certs, inspector) == final and
                   public(ready, certs)['record']['version'] == '9')
        finally:
            if process.poll() is None:
                stop(process)
        passed('grant-capacity', observe_capacity(binary, directory,
               directory / 'capacity.json', config, certs, controller, record))
        require(observe_expired_management(binary, directory,
                directory / 'expired.json', config, certs, controller,
                inspector, record), 'expired-key management failed')
        observed['expired-key-management'] = {
            'status': 'PARTIAL', 'track': 'local_tls_runtime',
            'reason': 'Expired signing keys and management were observed; '
                      'no protected-message authorization was exercised.'}
        passed('uncertain-commit', observe_uncertain_restart(binary, directory,
               directory / 'uncertain.json', config))
        executable_sha256 = sha(binary.read_bytes())

    require(set(observed) == LOCAL_CASES, 'local operator observations incomplete')
    observations = []
    for row in suite['cases']:
        result = observed.get(row['id']) or {
            'status': 'NOT_RUN', 'track': 'local_tls_runtime',
            'reason': PENDING_CASES[row['id']]}
        observations.append({'id': row['id'], 'parent_case_id': row['parent_case_id'],
                             **result})
    report = {
        'schema_version': 1, 'kind': 'registry-operator-local-observation',
        'protocol_version': '0.10.0', 'spec_revision': SPEC_REVISION,
        'vector_sha256': VECTOR_SHA256, 'subject_revisions': revisions,
        'service_executable_sha256': executable_sha256,
        'cases': observations, 'local_pass': len(LOCAL_CASES) - 1,
        'partial': 1, 'not_run': len(PENDING_CASES),
        'deployed_reg08': 'NOT_RUN',
        'conformance': 'NOT_ESTABLISHED',
    }
    check_report(report, root)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-root', type=Path, required=True)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = observe(args.service_root, args.go_root, args.spec_root)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Registry operator local observation: {report['local_pass']}/17 PASS; "
          f"{report['partial']} PARTIAL; {report['not_run']} NOT_RUN; "
          'conformance NOT_ESTABLISHED')
