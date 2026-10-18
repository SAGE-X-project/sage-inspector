"""Separate actual card Verifier memory controls from benign owned TLS execution."""
import argparse
import base64
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from a2a_card_observation import canonical, execute
from current_spec_catalog import load, require, sha
from owned_http_observation import decode64, module_info, MODULE_PATHS, CALLER, SERVER, EPOCH

ADAPTER = 'adapters/a2a-did-authority'
FIXTURE = 'vectors/0.10.0/a2a-did-authority-observations.json'
SUBJECT = 'verification/0.10.0/a2a-did/did-authority-subject.json'
FIXTURE_SHA = 'eadc03558144ae18af896d1b1911f260729f5e9224d85f3c016ce26e6c1ac1d9'
SUBJECT_SHA = '6661a90d8175db5dd3b206a8551fda2e5c0b05ea72067f5c0a9832dffc3d6a75'
NATIVE_IDS = {'bare', 'http'}
UNIT_IDS = {'baseline', 'matching-document-calibration', 'peer-document-different-key', 'alias-also-known-as', 'alias-equivalent-id', 'alias-canonical-id', 'alias-combined', 'peer-listed-signature-key', 'unavailable-source', 'missing-signing-key', 'revoked-signing-key', 'alias-expected-peer-mismatch', 'alternate-peer-calibration'}
GROUPS = {
    'didp-04-peer-document-ignored': {'baseline', 'matching-document-calibration', 'peer-document-different-key', 'peer-listed-signature-key', 'unavailable-source', 'missing-signing-key', 'revoked-signing-key'},
    'didp-04-received-alias': {'baseline', 'matching-document-calibration', 'alias-also-known-as', 'alias-equivalent-id', 'alias-canonical-id', 'alias-combined', 'alias-expected-peer-mismatch', 'alternate-peer-calibration'},
}
SOURCE_FILES = ('card.go', 'fixture.go', 'main.go', 'go.mod', 'go.sum')


def subject(root=ROOT):
    raw = (root / SUBJECT).read_bytes()
    require(sha(raw) == SUBJECT_SHA, 'authority subject drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'repository', 'revision', 'core_revision', 'modules'} and value['schema'] == 'sage-did-card-authority-subject-v1' and value['spec_revision'] == SPEC_REVISION and value['repository'] == 'SAGE-X-project/sage-adk' and set(value['modules']) == MODULE_PATHS, 'authority public subject')
    return value


def fixtures(root=ROOT):
    raw = (root / FIXTURE).read_bytes()
    require(sha(raw) == FIXTURE_SHA, 'authority fixture drift')
    value = load(raw)
    require(value['schema'] == 'sage-card-authority-fixtures-v1' and value['spec_revision'] == SPEC_REVISION and value['subject_revision'] == subject(root)['revision'] and value['scope'] == 'memory-only-signing-card-authority-controls' and value['epoch'] == EPOCH and value['target'] == 'https://inspection.invalid/authority', 'authority fixture identity')
    rows = value['cases']
    require(type(rows) is list and len(rows) == 13 and {r['id'] for r in rows} == UNIT_IDS, 'exact thirteen logical controls')
    result = {}
    for row in rows:
        require(set(row) == {'id', 'input_card_hex', 'signing_public_hex', 'source_mode', 'expected_peer', 'expected'}, 'closed authority case')
        inputs = {k: row[k] for k in ('id', 'input_card_hex', 'signing_public_hex', 'source_mode', 'expected_peer')}
        result[row['id']] = {**row, 'input_sha256': sha(canonical(inputs))}
    require(len({r['input_card_hex'] for r in rows}) == 9, 'nine distinct signed card byte strings')
    return value, result


def source_record(who, mode, fixture):
    public = fixture['public_keys']['C' if who == CALLER else 'A']
    keys = []
    if who == SERVER:
        keys.append({'name': 'kem', 'alg': 'x25519', 'state': 'accepted', 'material_hex': fixture['public_keys']['kem']})
    if mode in ('missing-sign', 'revoked-sign'):
        keys.append({'name': 'other', 'alg': 'ed25519', 'state': 'accepted', 'material_hex': fixture['public_keys']['B']})
    if mode != 'missing-sign':
        keys.append({'name': 'sign', 'alg': 'ed25519', 'state': 'revoked' if mode == 'revoked-sign' else 'accepted', 'material_hex': public})
    return {'did': who, 'controller': 'inspector-owned-operator', 'version': '17', 'state': 'active', 'keys': keys, 'service': fixture['target']}


def unit_matches(actual, case, fixture):
    try:
        require(type(actual) is dict and set(actual) == {'id', 'input_card_hex', 'signing_public_hex', 'source_mode', 'configured_expected_peer', 'std_signature_valid', 'result', 'source_records', 'eligible_interfaces'}, 'closed actual authority witness')
        require(all(actual[k] == case[k] for k in ('id', 'input_card_hex', 'signing_public_hex', 'source_mode')) and actual['configured_expected_peer'] == case['expected_peer'] and actual['std_signature_valid'] is True, 'actual configured inputs and independent signature')
        interfaces = [{'URL': fixture['target'], 'Tenant': ''}] if case['expected']['accepted'] else []
        require(canonical(actual['eligible_interfaces']) == canonical(interfaces), 'actual owned eligible interfaces')
        require(canonical(actual['result']) == canonical(case['expected']), 'actual authority decision and retained card bytes')
        expected = [] if case['source_mode'] == 'unavailable' else [source_record(d, case['source_mode'], fixture) for d in case['expected']['source_dids']]
        require(canonical(actual['source_records']) == canonical(expected), 'effective actual Source identity, key roles, state and service')
        return True
    except (ValueError, KeyError, TypeError):
        return False


def parse_units(raw, root=ROOT):
    fixture, cases = fixtures(root)
    require(type(raw) is bytes and len(raw) <= 16777216, 'bounded raw Go unit events')
    records, passes, failures = {}, set(), []
    package = 'github.com/sage-x-project/sage-inspector/adapters/a2a-did-authority'
    package_pass = False
    for line in raw.splitlines():
        event = load(line)
        require(type(event) is dict and event.get('Package') == package, 'one actual authority test package')
        action, test = event.get('Action'), event.get('Test', '')
        if action == 'fail':
            failures.append(test)
        if action == 'pass' and not test:
            package_pass = True
        if action == 'pass' and test.startswith('TestCardAuthority/'):
            name = test.removeprefix('TestCardAuthority/')
            require(name in cases and name not in passes, 'unique exact passed authority leaf')
            passes.add(name)
        output = event.get('Output', '')
        if 'AUTHORITY_OBSERVATION ' in output:
            require(action == 'output' and test.startswith('TestCardAuthority/'), 'authority witness attributed to its unit leaf')
            row = load(output.split('AUTHORITY_OBSERVATION ', 1)[1].strip())
            name = test.removeprefix('TestCardAuthority/')
            require(name in cases and row['id'] == name and name not in records, 'unique case-bound witness')
            records[name] = {'id': name, 'input_sha256': cases[name]['input_sha256'], 'actual': row}
    require(package_pass and not failures and passes == UNIT_IDS and set(records) == UNIT_IDS, 'all thirteen actual Go controls passed')
    require(all(unit_matches(r['actual'], cases[n], fixture) for n, r in records.items()), 'actual authority observations differ')
    return [records[n] for n in cases]


def native_matches(actual, fixture):
    try:
        fields = {'target', 'owner_type', 'ingress_type', 'card_hex', 'verified_card_hex', 'verified_did', 'verified_version', 'client_calls', 'tls_handshakes', 'handler_calls', 'handler_payloads_hex', 'replies_hex', 'errors', 'setup_reservations', 'accepted_requests', 'accepted_responses', 'source_reads', 'source_observations', 'records', 'eligible_interfaces'}
        require(type(actual) is dict and set(actual) == fields, 'closed benign native observation')
        target = actual['target']
        match = re.fullmatch(r'https://127\.0\.0\.1:([1-9][0-9]{0,4})/sage%2Fa\?client=%2f', target) if type(target) is str else None
        require(match is not None and int(match[1]) <= 65535 and actual['owner_type'] == '*a2abinding.HTTPTransportOwner' and actual['ingress_type'] == '*a2abinding.HTTPIngress', 'actual owned endpoint')
        counters = ('client_calls', 'tls_handshakes', 'handler_calls', 'accepted_requests', 'accepted_responses')
        require(all(type(actual[k]) is int and actual[k] == 1 for k in counters) and all(type(actual[k]) is int and actual[k] > 0 for k in ('source_reads', 'source_observations')), 'actual benign phases')
        require(canonical(actual['setup_reservations']) == b'[1,1]' and actual['errors'] == [''] and actual['handler_payloads_hex'] == [b' {"jsonrpc":"2.0","id":"inspection","method":"GetTask","params":{"id":"owned-task"}} '.hex()] and actual['replies_hex'] == [b'{"jsonrpc":"2.0","id":"inspection","result":{"ok":true}}'.hex()], 'actual benign payload and reservations')
        require(canonical(actual['eligible_interfaces']) == canonical([{'URL': target, 'Tenant': ''}]), 'actual benign eligible interface')
        raw = bytes.fromhex(actual['card_hex'])
        require(actual['verified_card_hex'] == actual['card_hex'] and actual['verified_did'] == SERVER and actual['verified_version'] == '17', 'actual Verifier retains complete received card')
        card = load(raw)
        signatures = card.pop('signatures')
        require(type(signatures) is list and len(signatures) == 1 and set(signatures[0]) == {'protected', 'signature'} and load(decode64(signatures[0]['protected'])) == {'alg': 'Ed25519', 'kid': SERVER + '#sign', 'typ': 'sage-a2a-card+jws'} and len(decode64(signatures[0]['signature'])) == 64, 'native signature framing only')
        calibration = next(c for c in fixture['cases'] if c['id'] == 'matching-document-calibration')
        expected = load(bytes.fromhex(calibration['input_card_hex']))
        del expected['signatures']
        expected['supportedInterfaces'][0]['url'] = target
        require(canonical(card) == canonical(expected), 'independent normalized complete native claims')
        records = actual['records']
        require(type(records) is list and 2 <= len(records) <= actual['source_reads'] + actual['source_observations'] and {r['did'] for r in records} == {CALLER, SERVER}, 'actual native Source observations')
        for row in records:
            who = 'C' if row['did'] == CALLER else 'A'
            require(canonical(row) == canonical({'did': row['did'], 'controller': 'inspector-owned-operator', 'version': '17', 'signing_hex': fixture['public_keys'][who], 'kem_hex': fixture['public_keys']['kem'] if row['did'] == SERVER else '', 'service': target, 'time': EPOCH}), 'native Source exact facts')
        return True
    except (ValueError, KeyError, TypeError, OverflowError):
        return False


def assess(native, units, root=ROOT):
    fixture, cases = fixtures(root)
    require(type(native) is list and len(native) <= 2 and type(units) is list and len(units) <= 13, 'bounded separate observations')
    native_results, unit_results = {}, {}
    for row in native:
        require(set(row) == {'id', 'input_sha256', 'actual'} and type(row['id']) is str and row['id'] in NATIVE_IDS and row['id'] not in native_results and row['input_sha256'] == sha(canonical({'completion': row['id']})), 'unique native selector')
        native_results[row['id']] = native_matches(row['actual'], fixture)
    for row in units:
        require(set(row) == {'id', 'input_sha256', 'actual'} and type(row['id']) is str and row['id'] in cases and row['id'] not in unit_results and row['input_sha256'] == cases[row['id']]['input_sha256'], 'unique composite unit input')
        unit_results[row['id']] = unit_matches(row['actual'], cases[row['id']], fixture)
    report = inventory(root)
    for row in report['cases']:
        required = GROUPS.get(row['id'])
        row['status'] = 'NOT_RUN'
        if required:
            seen = list(native_results.values()) + [v for n, v in unit_results.items() if n in required]
            row['status'] = 'FAIL' if False in seen else ('PARTIAL' if NATIVE_IDS <= native_results.keys() and required <= unit_results.keys() else 'NOT_RUN')
            row['coverage_notes'] = 'Public card Verifier: memory-only authority controls plus separate benign owned TLS. No core KEM/Rust/operating-authority or whole-case conformance proof.'
    report.update(kind='did-card-authority-observation', evidence_kind='reported-output', subject=subject(root), subject_manifest_sha256=SUBJECT_SHA, fixture_sha256=FIXTURE_SHA, historical_results_merged=False, native_observations=native, unit_observations=units, native_results=native_results, unit_results=unit_results, status_counts=dict(Counter(c['status'] for c in report['cases'])), scope={'source': 'PREVALIDATED_OWNED_FIXTURE_ONLY', 'negative_controls': 'MEMORY_ONLY_GO_UNIT_TESTS', 'transport': 'BENIGN_OWNED_TLS_ONLY', 'host_execution_guard': 'NOT_BOUND', 'operating_registry': 'NOT_BOUND', 'core_kem_authority': 'NOT_RUN', 'rust_authority': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED'})
    require(set(GROUPS) <= {c['id'] for c in report['cases']}, 'frozen authority linkage')
    return report


def compiled_modules(info, expected, revision):
    require(type(info) is dict and info.get('GoVersion') == 'go1.26.8' and info.get('Path') == 'github.com/sage-x-project/sage-inspector/adapters/a2a-did-authority' and type(info.get('Deps')) is list, 'authority compiler/package')
    deps = {}
    for row in info['Deps']:
        require(type(row) is dict and type(row.get('Path')) is str and row['Path'] not in deps and row.get('Replace') is None, 'unique compiled dependencies without replacement')
        deps[row['Path']] = row
    require(set(expected) <= deps.keys(), 'four public modules actually compiled')
    require(all(deps[p].get('Version') == v['Version'] and deps[p].get('Sum') == v['Sum'] for p, v in expected.items()), 'compiled module identity joined to metadata')
    settings = {}
    require(type(info.get('Settings')) is list, 'native build settings')
    for row in info['Settings']:
        require(type(row) is dict and set(row) == {'Key', 'Value'} and type(row['Key']) is str and type(row['Value']) is str and row['Key'] not in settings, 'unique typed build settings')
        settings[row['Key']] = row['Value']
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision) is not None and settings.get('vcs') == 'git' and settings.get('vcs.revision') == revision and settings.get('vcs.modified') == 'false', 'native compiled VCS identity and clean source')


def compiler_inputs(go, directory, env):
    package = load(execute([go, 'list', '-mod=readonly', '-json', '.'], directory, env).stdout)
    require(package.get('GoFiles') == ['card.go', 'fixture.go', 'main.go'] and not any(package.get(k) for k in ('CgoFiles', 'SFiles', 'SysoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SwigFiles', 'SwigCXXFiles', 'EmbedFiles')), 'closed native compiler inputs')
    return {p: sha((directory / p).read_bytes()) for p in SOURCE_FILES}


def observer_sources(root=ROOT):
    paths = ('scripts/did_authority_observation.py', 'scripts/check_did_authority_evidence.py', 'scripts/test_did_authority_observation.py', 'scripts/owned_http_observation.py', 'scripts/a2a_card_observation.py', 'scripts/a2a_did_catalog.py', 'scripts/current_spec_catalog.py', FIXTURE, SUBJECT, 'adapters/a2a-did-authority/main_test.go', 'verification/0.10.0/a2a-did/did-authority-fixture-construction.py.txt', 'docs/did-card-authority-inspection.md', '.github/workflows/did-card-authority-inspection.yml')
    return {p: sha((root / p).read_bytes()) for p in paths}


def run_native(go, root=ROOT, attempts=None):
    selected = subject(root)
    before = observer_sources(root)
    directory = root / ADAPTER
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='0')
    compiler = execute([go, 'version'], directory, env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', compiler) is not None, 'required authority compiler')
    revision = execute(['git', 'rev-parse', 'HEAD'], root, env).stdout.decode().strip()
    modules = module_info(go, directory, env, selected['modules'])
    source = compiler_inputs(go, directory, env)
    observations, traces = [], []
    with tempfile.TemporaryDirectory(prefix='sage-card-authority-') as tmp:
        binary = Path(tmp) / 'observer'
        execute([go, 'build', '-trimpath', '-o', str(binary), '.'], directory, env, timeout=180)
        digest = sha(binary.read_bytes())
        info = load(execute([go, 'version', '-m', '-json', str(binary)], directory, env).stdout)
        compiled_modules(info, selected['modules'], revision)
        for name in ('bare', 'http'):
            raw = canonical({'completion': name})
            done = subprocess.run([str(binary)], input=raw, capture_output=True, timeout=20, env=env, check=False)
            trace_row = {'id': name, 'input_hex': raw.hex(), 'input_sha256': sha(raw), 'stdout_hex': done.stdout.hex(), 'stdout_sha256': sha(done.stdout), 'stderr_hex': done.stderr.hex(), 'returncode': done.returncode}
            if attempts is not None:
                attempts.write(json.dumps(trace_row) + '\n')
                attempts.flush()
            require(done.returncode == 0 and len(done.stdout) <= 262144 and not done.stderr, 'bounded benign native process')
            observations.append({'id': name, 'input_sha256': sha(raw), 'actual': load(done.stdout)})
            traces.append(trace_row)
        require(digest == sha(binary.read_bytes()), 'authority native executable changed')
    require(source == compiler_inputs(go, directory, env) and modules == module_info(go, directory, env, selected['modules']) and before == observer_sources(root), 'authority inputs changed')
    report = assess(observations, [], root)
    require(all(report['native_results'].values()), 'benign native observation differs')
    report.update(evidence_kind='inspector-launched-benign-authority-native-processes', observer={'repository': 'SAGE-X-project/sage-inspector', 'revision': revision, 'source_sha256': before}, execution={'compiler': compiler, 'adapter_sha256': digest, 'adapter_source_sha256': source, 'modules': modules, 'build_info': info, 'process_count': len(observations), 'runtime': 'actual-public-owned-loopback-TLS-adapter', 'raw_trace': traces})
    return report
