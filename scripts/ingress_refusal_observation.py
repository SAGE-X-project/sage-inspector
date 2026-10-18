"""Inspect fixed memory ingress refusals and separate benign native TLS exchanges."""
import argparse
import base64
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from a2a_card_observation import canonical, execute
from current_spec_catalog import load, require, sha
import owned_http_observation as owned

ADAPTER = 'adapters/a2a-ingress-refusal'
FIXTURE = 'vectors/0.10.0/a2a-ingress-refusal-observations.json'
SUBJECT = 'verification/0.10.0/a2a-did/ingress-refusal-subject.json'
FIXTURE_SHA = '9fde77d2c802a1a306ba5bc29c945dd89c330660b8acef939ced51cad8d479a2'
SUBJECT_SHA = '36e27aef1ac5fe5cc7a011d67be2123aad2c7abb872d520a3d98b9125e6546de'
PACKAGE = 'github.com/sage-x-project/sage-adk/core/a2abinding'
PARENT = 'TestProtectedHTTPIngressRefusalEvidence010'
MODES = {'positive-calibration', 'bare-jsonrpc', 'legacy-unsigned', 'grpc-media-http1', 'h2-only'}
GROUPS = {'a2ab-01-bare-jsonrpc-body', 'a2ab-04-server-0-3-downgrade', 'a2ab-04-server-grpc-downgrade'}
TARGET = 'https://agents.example.com/a2a'
SERVER = 'did:sage:web:agents.example.com:billing-bot'
PEER = 'did:sage:web:agents.example.com:client'
EXTENSION = 'https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension'
WITNESS_KEYS = set('case transport target server_did local_did peer_did source_did source_version source_service tls_name offered negotiated handshake_failed handshake_error input_hex input_sha256 written response_frame_hex response_status response_body_hex authenticated_response response_error verified_payload_hex verified_success verified_code handler_calls handler_payloads_hex accepted_requests accepted_responses parser_trace core_trace calibration'.split())
SOURCES = ('scripts/ingress_refusal_observation.py', 'scripts/test_ingress_refusal_observation.py', 'scripts/check_ingress_refusal_evidence.py', FIXTURE, SUBJECT, 'verification/0.10.0/a2a-did/ingress-refusal-fixture-construction.py.txt', 'docs/ingress-refusal-inspection.md', '.github/workflows/ingress-refusal-inspection.yml', 'adapters/a2a-ingress-refusal/main_test.go', 'scripts/test_owned_http_observation.py', 'scripts/owned_http_observation.py', 'scripts/a2a_card_observation.py', 'scripts/a2a_did_catalog.py', 'scripts/current_spec_catalog.py')


def subject(root=ROOT):
    raw = (root / SUBJECT).read_bytes()
    require(sha(raw) == SUBJECT_SHA, 'ingress subject drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'repository', 'revision', 'core_revision', 'modules', 'package_sources'} and value['schema'] == 'sage-ingress-refusal-subject-v1' and value['spec_revision'] == SPEC_REVISION and value['repository'] == 'SAGE-X-project/sage-adk' and set(value['modules']) == owned.MODULE_PATHS, 'ingress subject identity')
    require(all(re.fullmatch('[0-9a-f]{40}', value[k]) for k in ('revision', 'core_revision')), 'public revisions')
    for module, dep in value['modules'].items():
        require(set(dep) == {'Version', 'Sum', 'GoModSum'} and type(dep['Version']) is str and all(re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', dep[k]) for k in ('Sum', 'GoModSum')), 'public module identity')
    require(value['modules']['github.com/sage-x-project/sage-adk']['Version'].endswith(value['revision'][:12]) and value['modules']['github.com/sage-x-project/sage']['Version'].endswith(value['core_revision'][:12]), 'subject module join')
    sources = value['package_sources']
    require(type(sources) is dict and len(sources) == 22 and {'go.mod', 'go.sum', 'core/a2abinding/schema.json'} <= sources.keys() and len([p for p in sources if p.startswith('core/a2abinding/') and p.endswith('.go')]) == 19 and all(type(p) is str and '..' not in p.split('/') and re.fullmatch('[0-9a-f]{64}', h) for p, h in sources.items()), 'selected public package sources')
    return value


def fixtures(root=ROOT):
    raw = (root / FIXTURE).read_bytes()
    require(sha(raw) == FIXTURE_SHA, 'ingress fixture drift')
    value = load(raw)
    require(set(value) == {'schema', 'spec_revision', 'subject_revision', 'scope', 'memory_cases', 'native', 'mapping'} and value['schema'] == 'sage-ingress-refusal-fixtures-v1' and value['spec_revision'] == SPEC_REVISION and value['subject_revision'] == subject(root)['revision'] and value['scope'] == 'memory-private-ingress-and-separate-benign-loopback-tls', 'fixture identity')
    require(value['memory_cases'] == sorted(MODES) and set(value['mapping']) == GROUPS and all(set(v) == MODES for v in value['mapping'].values()), 'all five controls required by every partial row')
    return value


def rawhex(value, maximum=65536):
    require(type(value) is str and len(value) <= 2 * maximum and re.fullmatch('(?:[0-9a-f]{2})*', value) is not None, 'bounded canonical hex')
    return bytes.fromhex(value)


def b64(value, length=None):
    result = owned.decode64(value)
    require(length is None or len(result) == length, 'base64url length')
    return result


def frame(raw):
    head, delimiter, body = raw.partition(b'\r\n\r\n')
    require(delimiter and len(head) < 16384 and len(body) < 16384, 'bounded HTTP frame')
    lines = head.decode('ascii').split('\r\n')
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(': ')
        require(colon and re.fullmatch('[A-Za-z0-9-]+', name) and name.lower() not in headers and all(32 <= ord(c) < 127 for c in value), 'unique plain headers')
        headers[name.lower()] = value
    require(re.fullmatch('0|[1-9][0-9]*', headers.get('content-length', '')) is not None and int(headers['content-length']) == len(body) and headers.get('connection') == 'close', 'exact HTTP body framing')
    return lines[0], headers, body


def positive(raw, response=False):
    start, headers, body = frame(raw)
    require(start == ('HTTP/1.1 200 OK' if response else 'POST /a2a HTTP/1.1'), 'positive start line')
    require(set(headers) == {'connection', 'content-length', 'content-type', 'content-digest', 'signature', 'signature-input', 'x-sage-did', 'x-sage-version'} | (set() if response else {'host', 'user-agent'}), 'positive header set')
    require(response or (headers['host'] == 'agents.example.com' and headers['user-agent'] == 'Go-http-client/1.1'), 'configured request authority')
    require(headers['content-type'] == 'application/json' and headers['content-digest'] == 'sha-256=:' + base64.b64encode(hashlib.sha256(body).digest()).decode() + ':' and headers['x-sage-did'] == (SERVER if response else PEER) and headers['x-sage-version'] == '0.10.0', 'positive digest and sender headers')
    value = load(body)
    common = set('context_id created did encoding expires id kid nonce recipient role session_id signature version'.split())
    require(type(value) is dict and set(value) == common | ({'data', 'message_id', 'request_hash', 'success'} if response else {'payload', 'metadata'}), 'closed positive envelope')
    require(value['did'] == (SERVER if response else PEER) and value['recipient'] == (PEER if response else SERVER) and value['kid'] == value['did'] + '#sign' and value['role'] == ('responder' if response else 'initiator') and value['version'] == '0.10.0' and value['encoding'] == 'session' and type(value['created']) is int and value['created'] == 100 and type(value['expires']) is int and value['expires'] == 130, 'positive role/key/time facts')
    for key in ['context_id', 'id']:
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', value[key]) is not None, 'UUIDv4 envelope identity')
    b64(value['nonce'], 16); b64(value['session_id'], 16); b64(value['signature'], 64)
    require(36 <= len(b64(value['data' if response else 'payload'])) <= 16384, 'cipher framing only; not Python decryption')
    require(value.get('success') is True if response else canonical(value['metadata']) == canonical({'a2a_extensions': EXTENSION, 'a2a_version': '1.0'}), 'response success/request metadata')
    components = '"@status" "@method";req "@target-uri";req "@authority";req "content-digest";req "signature";req "x-sage-version";req "content-type" "content-digest" "x-sage-did" "x-sage-version"' if response else '"@method" "@target-uri" "@authority" "content-type" "content-digest" "x-sage-did" "x-sage-version"'
    expected = 'sig1=(' + components + ');keyid="' + value['kid'] + '";alg="ed25519";created=100;expires=130;nonce="' + value['nonce'] + '";tag="sage-0.10.0"'
    require(headers['signature-input'] == expected and re.fullmatch(r'sig1=:[A-Za-z0-9+/]{86}==:', headers['signature']) is not None and len(base64.b64decode(headers['signature'][6:-1], validate=True)) == 64, 'profile HTTP signature framing; crypto belongs to actual Go call')
    return value, body


def unsigned(mode):
    body = b'{"jsonrpc":"2.0","id":"one","method":"SendMessage","params":{"message":{"messageId":"memory","role":"ROLE_USER","parts":[{"text":"inert"}]}}}'
    media = 'application/json'
    extra = '' if mode == 'legacy-unsigned' else 'A2A-Version: 1.0\r\nA2A-Extensions: ' + EXTENSION + '\r\n'
    if mode == 'grpc-media-http1':
        body, media = b'inert unsigned unit bytes', 'application/grpc'
    return ('POST /a2a HTTP/1.1\r\nHost: agents.example.com\r\nContent-Type: ' + media + '\r\nContent-Length: ' + str(len(body)) + '\r\nConnection: close\r\n' + extra + '\r\n').encode() + body, body


def memory(w):
    require(type(w) is dict and set(w) == WITNESS_KEYS and w['case'] in MODES, 'closed memory witness')
    mode = w['case']
    require(all(type(w[k]) is int and 0 <= w[k] <= 65536 for k in ['written', 'response_status', 'handler_calls', 'accepted_requests', 'accepted_responses']) and all(type(w[k]) is bool for k in ['handshake_failed', 'authenticated_response', 'verified_success']), 'strict witness counters and flags')
    require(w['transport'] == 'net.Pipe/TLS' and w['target'] == w['source_service'] == TARGET and w['server_did'] == w['local_did'] == w['source_did'] == SERVER and w['peer_did'] == PEER and w['source_version'] == '3' and w['tls_name'] == 'localhost', 'separate actual URI/Source/session/TLS facts')
    raw, response, body = rawhex(w['input_hex']), rawhex(w['response_frame_hex']), rawhex(w['response_body_hex'])
    require(w['input_sha256'] == sha(raw) and w['written'] == len(raw), 'emitted input linkage')
    h2, good = mode == 'h2-only', mode == 'positive-calibration'
    require(w['offered'] == (['h2'] if h2 else ['http/1.1']) and w['negotiated'] == ('' if h2 else 'http/1.1') and w['handshake_failed'] is h2 and w['handshake_error'] == ('remote error: tls: no application protocol' if h2 else ''), 'specific actual negotiation oracle')
    require(w['parser_trace'] == w['core_trace'] == ('NOT_REACHED' if h2 else 'NOT_OBSERVED'), 'hidden trace is not inferred from effects')
    require(w['handler_calls'] == w['accepted_requests'] == w['accepted_responses'] == int(good) and w['authenticated_response'] is good and w['verified_success'] is good and w['verified_code'] == '' and w['response_error'] == ('' if good or h2 else 'authentication failed'), 'actual acceptance and verified view')
    if good:
        request, request_body = positive(raw)
        reply, reply_body = positive(response, True)
        require(reply_body == body and reply['message_id'] == request['id'] and reply['request_hash'] == base64.urlsafe_b64encode(hashlib.sha256(canonical(request)).digest()).rstrip(b'=').decode() and reply['context_id'] == request['context_id'] and reply['session_id'] == request['session_id'] and reply['id'] != request['id'] and reply['nonce'] != request['nonce'], 'positive signed request correlation')
        require(w['response_status'] == 200 and w['verified_payload_hex'] == b'{"jsonrpc":"2.0","id":"one","result":{"ok":true}}'.hex() and w['handler_payloads_hex'] == [b'{"id":"one","jsonrpc":"2.0","method":"GetTask","params":{"id":"task"}}'.hex()] and w['calibration'] is None, 'actual normal decryption/Handler calibration')
    else:
        require(w['verified_payload_hex'] == '' and w['handler_payloads_hex'] == [], 'no usable result or Handler')
        if h2:
            require(not raw and not response and not body and w['response_status'] == 0 and w['calibration'] is None, 'ALPN stops before any HTTP')
        else:
            expected_raw, expected_body = unsigned(mode)
            require(raw == expected_raw and w['response_status'] == 401 and body == b'authentication failed\n' and response == b'HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 22\r\nContent-Type: text/plain\r\n\r\nauthentication failed\n', 'exact inert refusal frames')
            calibration = {'scope': 'separate-fresh-memory-fixture', 'parser_error': '', 'body_hex': expected_body.hex(), 'open_error': 'authentication failed', 'returned_request': False, 'accepted_requests': 0}
            require(canonical(w['calibration']) == canonical(calibration), 'independent separately scoped parser/core calibration')
    return True


def witnesses(raw):
    require(type(raw) is bytes and len(raw) <= 2097152 and raw.endswith(b'\n'), 'bounded complete test2json stream')
    buffers, found, passed, started = {}, {}, [], []
    leaves = {PARENT + '/' + mode: mode for mode in MODES}
    package_pass = 0
    for line in raw.splitlines():
        e = load(line)
        require(type(e) is dict and e.get('Package') == PACKAGE and e.get('Action') in {'start', 'run', 'pause', 'cont', 'output', 'pass'} and (not e.get('Test') or e['Test'] in leaves or e['Test'] == PARENT), 'exact selected package/test events; no skip/fail')
        test = e.get('Test', '')
        if e['Action'] == 'run': started.append(test)
        if e['Action'] == 'pass':
            if test: passed.append(test)
            else: package_pass += 1
        if e['Action'] == 'output':
            output = e.get('Output')
            require(type(output) is str and len(output.encode()) <= 4096, 'bounded test output fragment')
            buffers[test] = buffers.get(test, '') + output
            require(len(buffers[test].encode()) <= 131072, 'bounded per-test line')
            while '\n' in buffers[test]:
                text, buffers[test] = buffers[test].split('\n', 1)
                marker = 'INGRESS_MEMORY_OBSERVATION '
                if marker in text:
                    require(test in leaves and text.count(marker) == 1, 'witness attributed to exact leaf')
                    w = load(text.split(marker, 1)[1])
                    require(w.get('case') == leaves[test] and w['case'] not in found and memory(w), 'unique actual memory observation')
                    found[w['case']] = w
    require(all(not b for b in buffers.values()) and Counter(passed) == Counter(started) == Counter([PARENT, *leaves]) and package_pass == 1 and set(found) == MODES, 'complete exactly once test/witness set')
    return found


def native_match(actual, fixture):
    additions = {'verified_card_hex', 'verified_did', 'verified_version', 'eligible_interfaces'}
    require(type(actual) is dict and additions <= actual.keys(), 'retained public Verifier view')
    require(actual['verified_card_hex'] == actual['card_hex'] and actual['verified_did'] == owned.SERVER and actual['verified_version'] == '17' and canonical(actual['eligible_interfaces']) == canonical([{'URL': actual['target'], 'Tenant': ''}]), 'actual verified card facts')
    expect = {'outcome': 'success', 'client_calls': 1, 'tls_handshakes': 1, 'handler_calls': 1, 'accepted_requests': 1, 'accepted_responses': 1, 'handler_payloads_hex': [fixture['request_hex']]}
    require(owned.matches({k: v for k, v in actual.items() if k not in additions}, {'input': {'mode': 'success'}, 'expected': expect}, fixture), 'benign native fixture/Source/Handler/output facts')
    return True


def assess(memory_rows, native_rows, root=ROOT):
    fixture, selected = fixtures(root), subject(root)
    require(type(memory_rows) is dict and set(memory_rows) <= MODES and all(k == w.get('case') and memory(w) for k, w in memory_rows.items()), 'observed memory set')
    require(type(native_rows) is dict and set(native_rows) <= {'bare', 'http'} and all(native_match(w, fixture['native']) for w in native_rows.values()), 'separate normal native set')
    complete = set(memory_rows) == MODES and set(native_rows) == {'bare', 'http'}
    report = inventory(root)
    for row in report['cases']:
        row['status'] = 'PARTIAL' if complete and row['id'] in GROUPS else 'NOT_RUN'
        if row['id'] in GROUPS: row['coverage_notes'] = 'Memory-only isolated ingress refusal with separate benign TLS; actual deployed alternate gRPC/legacy listeners remain unobserved.'
    report.update(kind='protected-ingress-refusal-observation', evidence_kind='reported-output', subject=selected, subject_manifest_sha256=SUBJECT_SHA, fixture_sha256=FIXTURE_SHA, memory_observations=memory_rows, native_observations=native_rows, status_counts=dict(Counter(c['status'] for c in report['cases'])), historical_results_merged=False, scope={'memory_transport': 'PRIVATE_INGRESS_NET_PIPE_TLS_UNIT', 'normal_native': 'SEPARATE_OWNED_LOOPBACK_TLS', 'source': 'PREVALIDATED_FIXTURE_ONLY', 'connection_internal_trace': 'NOT_OBSERVED_EXCEPT_ALPN_NOT_REACHED', 'direct_calibration': 'SEPARATE_FRESH_FIXTURE', 'actual_grpc_SendMessage': 'NOT_OBSERVED', 'operating_registry': 'NOT_BOUND', 'host_execution_guard': 'NOT_BOUND', 'full_conformance': 'NOT_ESTABLISHED'})
    return report


def observer_sources(root=ROOT):
    return {p: sha((root / p).read_bytes()) for p in SOURCES}


def selected_sources(directory, expected):
    actual = {p: sha((directory / p).read_bytes()) for p in expected}
    require(actual == expected, 'verified public package bytes changed')
    return actual


def public_test(go, root, env, selected, output):
    build_record = output.with_name('ingress-refusal-test-build-info.json')
    require(all(not path.exists() and not path.is_symlink() for path in (output, build_record)), 'new exclusive memory evidence path required')
    directory = root / ADAPTER
    dep = selected['modules']['github.com/sage-x-project/sage-adk']
    download = load(execute([go, 'mod', 'download', '-json', 'github.com/sage-x-project/sage-adk@' + dep['Version']], directory, env).stdout)
    require(download.get('Path') == 'github.com/sage-x-project/sage-adk' and all(download.get(k) == v for k, v in dep.items()) and download.get('Replace') is None and type(download.get('Dir')) is str, 'public module download h1 identity')
    with tempfile.TemporaryDirectory(prefix='sage-ingress-public-unit-') as tmp:
        copied = Path(tmp) / 'module'
        shutil.copytree(download['Dir'], copied)
        for folder in [copied, *(p for p in copied.rglob('*') if p.is_dir())]:
            folder.chmod(folder.stat().st_mode | 0o700)
        sources = selected_sources(copied, selected['package_sources'])
        package = copied / 'core/a2abinding'
        listing = load(execute([go, 'list', '-mod=readonly', '-json', '.'], package, env).stdout)
        inputs = set(listing.get('GoFiles', []) + listing.get('TestGoFiles', []) + listing.get('XTestGoFiles', []) + listing.get('EmbedFiles', []))
        require(listing.get('ImportPath') == PACKAGE and inputs == {p.rsplit('/', 1)[1] for p in sources if p.startswith('core/a2abinding/')} and not any(listing.get(k) for k in ['CgoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SFiles', 'SysoFiles', 'SwigFiles', 'SwigCXXFiles']), 'complete selected package compile/embed inventory')
        dependencies = owned.module_info(go, copied, env, {p: v for p, v in selected['modules'].items() if p != 'github.com/sage-x-project/sage-adk'})
        binary = Path(tmp) / 'ingress.test'
        build = [go, 'test', '-mod=readonly', '-race', '-c', '-o', str(binary), './core/a2abinding']
        execute(build, copied, env, timeout=240)
        info_raw = execute([go, 'version', '-m', '-json', str(binary)], copied, env).stdout
        with build_record.open('xb') as evidence:
            evidence.write(info_raw)
        info = load(info_raw)
        require(info.get('GoVersion') == 'go1.26.8' and info.get('Path') == PACKAGE + '.test' and build_settings(info).get('-race') == 'true', 'actual race test compiler; not compiled dependency graph')
        digest = sha(binary.read_bytes())
        command = [go, 'tool', 'test2json', '-t', '-p', PACKAGE, str(binary), '-test.v=test2json', '-test.run=^' + PARENT + '$', '-test.count=1', '-test.timeout=30s']
        done = subprocess.run(command, cwd=copied, env=env, capture_output=True, timeout=60, check=False)
        with output.open('xb') as evidence:
            evidence.write(done.stdout)
        require(done.returncode == 0 and done.stderr == b'', 'actual selected unit process; raw output retained')
        observed = witnesses(done.stdout)
        require(sha(binary.read_bytes()) == digest and sources == selected_sources(copied, selected['package_sources']), 'public unit source/binary changed')
    return observed, {'download': {k: download[k] for k in ('Path', 'Version', 'Sum', 'GoModSum')}, 'package_source_sha256': sources, 'package_inputs': {k: listing.get(k, []) for k in ('GoFiles', 'TestGoFiles', 'XTestGoFiles', 'EmbedFiles')}, 'dependencies': dependencies, 'test_binary_sha256': digest, 'build_info': info, 'build_command': build, 'test_command': command, 'execution_directory': str(copied), 'raw_test_sha256': sha(done.stdout), 'test_returncode': done.returncode, 'test_stderr_hex': done.stderr.hex(), 'scope': 'verified public module as test main; no compiled dependency metadata claim'}


def build_settings(info):
    require(type(info) is dict and type(info.get('Settings')) is list, 'typed build settings')
    settings = {}
    for row in info['Settings']:
        require(type(row) is dict and set(row) in ({'Key'}, {'Key', 'Value'}) and type(row['Key']) is str and bool(row['Key']) and type(row.get('Value', '')) is str and row['Key'] not in settings, 'unique typed build settings')
        # Go debug.BuildSetting.Value uses json omitempty: absence is empty,
        # never true. Mandatory race/VCS values are checked by their callers.
        settings[row['Key']] = row.get('Value', '')
    return settings


def compiled_native(info, expected, revision):
    require(type(info) is dict and info.get('GoVersion') == 'go1.26.8' and info.get('Path') == 'github.com/sage-x-project/sage-inspector/' + ADAPTER and type(info.get('Deps')) is list, 'native compiler/package')
    deps = {}
    for row in info['Deps']:
        require(type(row) is dict and type(row.get('Path')) is str and row['Path'] not in deps and row.get('Replace') is None, 'unique native dependencies without replacement')
        deps[row['Path']] = row
    require(all(p in deps and all(deps[p].get(k) == values[k] for k in ('Version', 'Sum')) for p, values in expected.items()), 'all four native public compiled modules')
    settings = build_settings(info)
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision) is not None and settings.get('vcs') == 'git' and settings.get('vcs.revision') == revision and settings.get('vcs.modified') == 'false', 'clean native Git checkout identity')


def run_native(go, directory, root=ROOT):
    selected = subject(root); before = observer_sources(root)
    env = os.environ.copy(); env.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-mod=readonly', GOPROXY='off', CGO_ENABLED='1')
    require(execute([go, 'version'], root / ADAPTER, env).stdout.strip() == b'go version go1.26.8 linux/amd64', 'required remote compiler')
    modules = owned.module_info(go, root / ADAPTER, env, selected['modules'])
    memory_rows, memory_execution = public_test(go, root, env, selected, directory / 'ingress-refusal-memory-tests.jsonl')
    adapter = root / ADAPTER
    source = {p: sha((adapter / p).read_bytes()) for p in ('main.go', 'fixture.go', 'card.go', 'go.mod', 'go.sum')}
    listing = load(execute([go, 'list', '-mod=readonly', '-json', '.'], adapter, env).stdout)
    require(listing.get('GoFiles') == ['card.go', 'fixture.go', 'main.go'] and not any(listing.get(k) for k in ('CgoFiles', 'SFiles', 'SysoFiles', 'EmbedFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SwigFiles', 'SwigCXXFiles')), 'native production compile inputs')
    observations, traces = {}, []
    with tempfile.TemporaryDirectory(prefix='sage-ingress-native-') as tmp:
        binary = Path(tmp) / 'observer'
        execute([go, 'build', '-trimpath', '-o', str(binary), '.'], adapter, env, timeout=240)
        digest = sha(binary.read_bytes()); info = load(execute([go, 'version', '-m', '-json', str(binary)], adapter, env).stdout)
        revision = execute(['git', 'rev-parse', 'HEAD'], root, env).stdout.decode().strip()
        compiled_native(info, selected['modules'], revision)
        with (directory / 'ingress-refusal-native.attempts.jsonl').open('x') as attempts:
            for completion in ('bare', 'http'):
                raw = canonical({'completion': completion})
                done = subprocess.run([str(binary)], input=raw, env=env, capture_output=True, timeout=20, check=False)
                trace = {'id': completion, 'input_hex': raw.hex(), 'input_sha256': sha(raw), 'stdout_hex': done.stdout.hex(), 'stdout_sha256': sha(done.stdout), 'stderr_hex': done.stderr.hex(), 'returncode': done.returncode}
                attempts.write(json.dumps(trace) + '\n'); attempts.flush(); traces.append(trace)
                require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 262144, 'bounded benign native process')
                observations[completion] = load(done.stdout)
        require(digest == sha(binary.read_bytes()), 'native binary changed')
    require(source == {p: sha((adapter / p).read_bytes()) for p in source} and modules == owned.module_info(go, adapter, env, selected['modules']) and before == observer_sources(root), 'observer/source/public modules changed')
    report = assess(memory_rows, observations, root)
    require(report['status_counts'] == {'PARTIAL': 3, 'NOT_RUN': 580}, 'complete bounded evidence')
    report.update(evidence_kind='inspector-launched-memory-unit-and-separate-benign-native', observer={'repository': 'SAGE-X-project/sage-inspector', 'revision': revision, 'source_sha256': before}, execution={'memory': memory_execution, 'native': {'adapter_sha256': digest, 'adapter_source_sha256': source, 'modules': modules, 'build_info': info, 'raw_trace': traces, 'process_count': 2}})
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    report = run_native('go', args.directory)
    with (args.directory / 'ingress-refusal-native.json').open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print('Ingress refusal inspection: 3 PARTIAL / 580 NOT_RUN; full conformance NOT_ESTABLISHED')
