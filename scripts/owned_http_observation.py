"""Inspect an owned public A2A HTTP path as a separate, bounded fixture subject."""
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

ADAPTER = 'adapters/a2a-owned-http'
FIXTURE = 'vectors/0.10.0/a2a-owned-http-observations.json'
SUBJECT = 'verification/0.10.0/a2a-did/owned-http-subject.json'
FIXTURE_SHA = 'ffbdf688bf13f3d51ff4773dd4f35d862a892e95fbe88779bc4969e1163e6cda'
SUBJECT_SHA = '4e1c3f0e2717e5b003af4048eefcac370eee79456ef082b70df1c00e0a55cc41'
CALLER = 'did:sage:web:inspection.example:caller'
SERVER = 'did:sage:web:inspection.example:service'
EPOCH = 1700000000
GOOD = {'success', 'repeat', 'unsupported'}
MODES = {'success', 'repeat', 'unsupported', 'source-after-setup', 'expired-after-setup', 'cancel-after-setup', 'close-after-setup', 'source-after-handler', 'expired-after-handler', 'close-during-handler', 'cancel-during-handler'}
IDS = {h + '/' + m for h in ('bare', 'http') for m in MODES}
GROUPS = {
    'a2ab-01-jsonrpc-in-payload': {h + '/' + m for h in ('bare', 'http') for m in ('success', 'repeat')},
    'a2ab-01-a2a-error-in-data': {h + '/unsupported' for h in ('bare', 'http')},
    'a2ab-02-version-1-0': {h + '/' + m for h in ('bare', 'http') for m in GOOD},
    'a2ab-07-abort-no-retry': {h + '/' + m for h in ('bare', 'http') for m in MODES - GOOD},
}
MODULE_PATHS = {'github.com/sage-x-project/sage-adk', 'github.com/sage-x-project/sage', 'github.com/sage-x-project/did-go', 'github.com/sage-x-project/did-go/advanced/sage'}


def subject(root=ROOT):
    raw = (root / SUBJECT).read_bytes()
    require(sha(raw) == SUBJECT_SHA, 'owned HTTP subject drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'repository', 'revision', 'core_revision', 'modules'} and value['schema'] == 'sage-owned-http-subject-v1' and value['spec_revision'] == SPEC_REVISION and value['repository'] == 'SAGE-X-project/sage-adk' and set(value['modules']) == MODULE_PATHS, 'owned subject identity')
    for path, dep in value['modules'].items():
        require(set(dep) == {'Version', 'Sum', 'GoModSum'} and type(dep['Version']) is str and all(re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', dep[k]) is not None for k in ('Sum', 'GoModSum')), 'public owned dependency')
    require(value['modules']['github.com/sage-x-project/sage-adk']['Version'].endswith(value['revision'][:12]) and value['modules']['github.com/sage-x-project/sage']['Version'].endswith(value['core_revision'][:12]), 'owned revision linkage')
    return value


def fixtures(root=ROOT):
    raw = (root / FIXTURE).read_bytes()
    require(sha(raw) == FIXTURE_SHA, 'owned HTTP fixture drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'subject_revision', 'scope', 'epoch', 'public_keys', 'request_hex', 'reply_hex', 'cases'} and value['schema'] == 'sage-owned-http-fixtures-v1' and value['spec_revision'] == SPEC_REVISION and value['subject_revision'] == subject(root)['revision'] and value['scope'] == 'owned-loopback-tls-prevalidated-fixture-authority' and value['epoch'] == EPOCH, 'owned fixture identity')
    rows = value['cases']
    require(type(rows) is list and len(rows) == 22 and {c['id'] for c in rows} == IDS, 'complete owned scenario set')
    for row in rows:
        require(set(row) == {'id', 'input', 'expected'} and set(row['input']) == {'mode', 'completion'} and row['id'] == row['input']['completion'] + '/' + row['input']['mode'], 'owned input linkage')
    return value, {c['id']: {**c, 'input_sha256': sha(canonical(c['input']))} for c in rows}


def decode64(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]+', value) is not None, 'canonical fixture base64url')
    result = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    require(base64.urlsafe_b64encode(result).rstrip(b'=').decode() == value, 'base64url spelling')
    return result


def card_facts(raw, target):
    require(type(raw) is str and len(raw) <= 32768 and re.fullmatch('(?:[0-9a-f]{2})+', raw) is not None, 'owned card bytes')
    card = load(bytes.fromhex(raw))
    require(type(card) is dict, 'owned card object')
    signatures = card.pop('signatures', None)
    require(type(signatures) is list and len(signatures) == 1 and set(signatures[0]) == {'protected', 'signature'}, 'one public fixture signature')
    require(load(decode64(signatures[0]['protected'])) == {'alg': 'Ed25519', 'kid': SERVER + '#sign', 'typ': 'sage-a2a-card+jws'} and len(decode64(signatures[0]['signature'])) == 64, 'owned card signature framing')
    expected = {'name': 'inspection fixture', 'description': '', 'version': '1', 'supportedInterfaces': [{'url': target, 'protocolBinding': 'https://sage-x-project.github.io/sage-spec/a2a/0.10.0/binding', 'protocolVersion': '1.0'}], 'capabilities': {'streaming': False, 'extensions': [{'uri': 'https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension', 'required': True, 'params': {'sageVersion': '0.10.0', 'did': SERVER, 'recordVersion': '17', 'issued': EPOCH, 'expires': EPOCH + 5}}]}, 'defaultInputModes': ['application/json'], 'defaultOutputModes': ['application/json'], 'skills': [{'id': 'inspection', 'name': 'inspection', 'description': '', 'tags': ['inspection']}]}
    require(canonical(card) == canonical(expected), 'independent closed card facts')
    # Signature cryptography belongs to the actual subject and independent Go
    # standard-library fixture units; this Python check claims facts/framing only.


def matches(actual, case, fixture):
    try:
        require(type(actual) is dict and set(actual) == {'target', 'owner_type', 'ingress_type', 'card_hex', 'client_calls', 'tls_handshakes', 'handler_calls', 'handler_payloads_hex', 'replies_hex', 'errors', 'setup_reservations', 'accepted_requests', 'accepted_responses', 'source_reads', 'source_observations', 'records'}, 'closed native observation')
        target = actual['target']
        parsed = re.fullmatch(r'https://127\.0\.0\.1:([1-9][0-9]{0,4})/sage%2Fa\?client=%2f', target) if type(target) is str else None
        require(parsed is not None and int(parsed[1]) <= 65535 and actual['owner_type'] == '*a2abinding.HTTPTransportOwner' and actual['ingress_type'] == '*a2abinding.HTTPIngress', 'actual owned endpoint/types')
        expected, mode = case['expected'], case['input']['mode']
        counters = ('client_calls', 'tls_handshakes', 'handler_calls', 'accepted_requests', 'accepted_responses', 'source_reads', 'source_observations')
        require(all(type(actual[k]) is int and 0 <= actual[k] <= 1000 for k in counters), 'typed actual counters')
        require(all(actual[k] == expected[k] for k in counters[:5]) and actual['source_reads'] > 0 and actual['source_observations'] > 0, 'phase-specific observed calls and acceptance')
        require(type(actual['setup_reservations']) is list and len(actual['setup_reservations']) == 2 and all(type(n) is int and n == 1 for n in actual['setup_reservations']), 'separate real handshake reservations')
        require(actual['handler_payloads_hex'] == expected['handler_payloads_hex'], 'exact actual Handler bytes')
        require(type(actual['errors']) is list and type(actual['replies_hex']) is list and len(actual['errors']) == len(actual['replies_hex']) == expected['client_calls'] and all(type(v) is str and len(v) <= 512 for v in actual['errors']), 'bounded real replies/errors')
        if expected['outcome'] == 'refused':
            require(actual['replies_hex'] == [''] and actual['errors'] == ['authentication failed'], 'refused exchange produced no usable result')
        else:
            require(actual['errors'] == [''] * expected['client_calls'], 'successful actual calls')
            if expected['outcome'] == 'success':
                require(actual['replies_hex'] == [fixture['reply_hex']] * expected['client_calls'], 'exact protected result bytes')
            else:
                require(len(actual['replies_hex']) == 1 and load(bytes.fromhex(actual['replies_hex'][0])) == {'jsonrpc': '2.0', 'id': 'inspection', 'error': {'code': -32004, 'message': 'Unsupported operation'}}, 'authenticated A2A error result')
        card_facts(actual['card_hex'], target)
        records = actual['records']
        require(type(records) is list and 2 <= len(records) <= actual['source_reads'] + actual['source_observations'] and {r['did'] for r in records} == {CALLER, SERVER}, 'real fixture Source records')
        for row in records:
            require(type(row) is dict and set(row) == {'did', 'controller', 'version', 'signing_hex', 'kem_hex', 'service', 'time'}, 'closed fixture record view')
            who = 'caller' if row['did'] == CALLER else 'server'
            require(row['controller'] == 'inspector-owned-operator' and row['version'] == '17' and row['signing_hex'] == fixture['public_keys'][who] and row['kem_hex'] == (fixture['public_keys']['kem'] if who == 'server' else '') and row['service'] == target and type(row['time']) is int and EPOCH <= row['time'] <= EPOCH + 6, 'independent Source identity/key/service facts')
        if mode.startswith('expired-'):
            require(max(r['time'] for r in records) == EPOCH + 6, 'expiry control reached actual Source')
        if mode.startswith('source-'):
            require(len(records) < actual['source_reads'] + actual['source_observations'], 'actual unavailable Source attempt')
        return True
    except (ValueError, KeyError, TypeError, OverflowError):
        return False


def assess(observations, root=ROOT):
    fixture, cases = fixtures(root)
    require(type(observations) is list and len(observations) <= 22, 'bounded owned observations')
    results = {}
    for row in observations:
        require(type(row) is dict and set(row) == {'id', 'input_sha256', 'actual'} and type(row['id']) is str and row['id'] in cases and row['id'] not in results and row['input_sha256'] == cases[row['id']]['input_sha256'], 'unique exact observed input')
        results[row['id']] = matches(row['actual'], cases[row['id']], fixture)
    statuses = {key: ('FAIL' if any(not results[n] for n in required & results.keys()) else ('PARTIAL' if required <= results.keys() else 'NOT_RUN')) for key, required in GROUPS.items()}
    report = inventory(root)
    require(set(GROUPS) <= {c['id'] for c in report['cases']}, 'frozen owned contract linkage')
    for row in report['cases']:
        row['status'] = statuses.get(row['id'], 'NOT_RUN')
        if row['id'] in GROUPS:
            row['coverage_notes'] = 'Actual fixed-peer owned TLS, inert Handler, fixture Source and phase-specific refusal; no whole-case conformance.'
    report.update(kind='owned-a2a-http-observation', evidence_kind='reported-output', subject=subject(root), subject_manifest_sha256=SUBJECT_SHA, fixture_sha256=FIXTURE_SHA, historical_results_merged=False, observations=observations, scenario_results=results, status_counts=dict(Counter(c['status'] for c in report['cases'])), scope={'transport': 'PUBLIC_OWNED_TLS_ADAPTER', 'source': 'PREVALIDATED_OWNED_FIXTURE_ONLY', 'host_execution_guard': 'NOT_BOUND', 'operating_registry': 'NOT_BOUND', 'automatic_owner_retirement': 'NOT_OBSERVED_BY_THIS_OBSERVER', 'peer_document_alias_authority': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED'})
    return report


def module_info(go, directory, env, expected):
    result = []
    for path, values in expected.items():
        module = load(execute([go, 'list', '-mod=readonly', '-m', '-json', path], directory, env).stdout)
        require(module.get('Path') == path and not module.get('Main') and module.get('Replace') is None and all(module.get(k) == v for k, v in values.items()), 'actual public module identity')
        result.append({'Path': path, **values})
    require(execute([go, 'mod', 'verify'], directory, env).stdout == b'all modules verified\n', 'public module cache')
    return result


def compiled_modules(info, expected):
    require(type(info) is dict and info.get('GoVersion') == 'go1.26.8' and info.get('Path') == 'github.com/sage-x-project/sage-inspector/adapters/a2a-owned-http' and type(info.get('Deps')) is list, 'native compiler and package')
    deps = {}
    for row in info['Deps']:
        require(type(row) is dict and type(row.get('Path')) is str and row['Path'] not in deps and row.get('Replace') is None, 'unique compiled modules without replacement')
        deps[row['Path']] = row
    require(set(expected) <= deps.keys(), 'all four public modules compiled')
    for path, values in expected.items():
        require(deps[path].get('Version') == values['Version'] and deps[path].get('Sum') == values['Sum'], 'compiled/list module join')
    # BuildInfo contains no GoModSum; that separate proof remains in module_info.


def compiler_inputs(go, directory, env):
    package = load(execute([go, 'list', '-mod=readonly', '-json', '.'], directory, env).stdout)
    require(package.get('GoFiles') == ['fixture.go', 'main.go'] and
            not any(package.get(k) for k in ('CgoFiles', 'SFiles', 'SysoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SwigFiles', 'SwigCXXFiles', 'EmbedFiles')), 'unexpected owned compiler inputs')
    return {p: sha((directory / p).read_bytes()) for p in ('fixture.go', 'main.go', 'go.mod', 'go.sum')}


def observer_sources(root):
    paths = ('scripts/owned_http_observation.py', 'scripts/a2a_card_observation.py', 'scripts/a2a_did_catalog.py', 'scripts/current_spec_catalog.py', FIXTURE, SUBJECT, 'scripts/test_owned_http_observation.py', 'scripts/check_owned_http_evidence.py', 'adapters/a2a-owned-http/main_test.go', 'verification/0.10.0/a2a-did/owned-http-fixture-construction.py.txt', 'docs/owned-http-inspection.md', '.github/workflows/owned-http-inspection.yml')
    return {p: sha((root / p).read_bytes()) for p in paths}


def run_native(go, root=ROOT, attempts=None):
    selected = subject(root)
    before = observer_sources(root)
    directory = root / ADAPTER
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='0')
    compiler = execute([go, 'version'], directory, env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)', compiler) is not None, 'required owned compiler')
    modules = module_info(go, directory, env, selected['modules'])
    source = compiler_inputs(go, directory, env)
    require(set(source) == {'main.go', 'fixture.go', 'go.mod', 'go.sum'}, 'complete owned native sources')
    _, cases = fixtures(root)
    observations, raw_trace = [], []
    with tempfile.TemporaryDirectory(prefix='sage-owned-http-inspector-') as tmp:
        binary = Path(tmp) / 'observer'
        execute([go, 'build', '-trimpath', '-o', str(binary), '.'], directory, env, timeout=180)
        digest = sha(binary.read_bytes())
        info = load(execute([go, 'version', '-m', '-json', str(binary)], directory, env).stdout)
        compiled_modules(info, selected['modules'])
        for case in cases.values():
            raw = canonical(case['input'])
            done = subprocess.run([str(binary)], input=raw, capture_output=True, timeout=20, env=env, check=False)
            trace_row = {'id': case['id'], 'input_hex': raw.hex(), 'input_sha256': sha(raw), 'stdout_hex': done.stdout.hex(), 'stdout_sha256': sha(done.stdout), 'stderr_hex': done.stderr.hex(), 'returncode': done.returncode}
            if attempts is not None:
                attempts.write(json.dumps(trace_row) + '\n')
                attempts.flush()
            require(done.returncode == 0 and len(done.stdout) <= 262144 and not done.stderr, 'bounded clean owned native process')
            observations.append({'id': case['id'], 'input_sha256': sha(raw), 'actual': load(done.stdout)})
            raw_trace.append(trace_row)
        require(digest == sha(binary.read_bytes()), 'owned native executable changed')
    require(source == compiler_inputs(go, directory, env) and modules == module_info(go, directory, env, selected['modules']), 'owned build inputs changed')
    require(before == observer_sources(root), 'owned observation sources changed')
    report = assess(observations, root)
    report.update(evidence_kind='inspector-launched-native-owned-http-processes', observer={'repository': 'SAGE-X-project/sage-inspector', 'revision': execute(['git', 'rev-parse', 'HEAD'], root, env).stdout.decode().strip(), 'source_sha256': before}, execution={'compiler': compiler, 'adapter_sha256': digest, 'adapter_source_sha256': source, 'modules': modules, 'build_info': info, 'process_count': len(observations), 'runtime': 'actual-public-owned-loopback-TLS-adapter', 'raw_trace': raw_trace})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.native:
            with args.output.with_suffix('.attempts.jsonl').open('x') as attempts:
                report = run_native(args.go, attempts=attempts)
        else:
            report = assess([])
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        require(not report['status_counts'].get('FAIL', 0), 'owned contract finding; raw FAIL preserved')
        if args.native:
            require(len(report['scenario_results']) == 22 and all(report['scenario_results'].values()) and report['status_counts'] == {'PARTIAL': 4, 'NOT_RUN': 579}, 'incomplete bounded owned observation')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Owned HTTP inspection FAIL: ' + str(error) + '\n')
    print('Owned HTTP inspection: ' + str(report['status_counts']) + '; full conformance NOT_ESTABLISHED')


if __name__ == '__main__':
    main()
