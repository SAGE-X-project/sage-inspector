"""Inspect fixed paired-core key authority units; never infer operating trust."""
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from current_spec_catalog import load, require, sha

BASE = 'verification/0.10.0/core-key-authority'
SUBJECT = 'verification/0.10.0/a2a-did/core-key-authority-subject.json'
FIXTURE = 'vectors/0.10.0/core-key-authority-observations.json'
SUBJECT_SHA = '6c8f4bc2f99854e6377ccaa5b135079c80d4575f4d01ca2149095aae5e67a731'
FIXTURE_SHA = '86a54eeaf893142bac12ee53cf16f801fca09cba6309fac09d156a9c37d5c046'
A = 'did:sage:web:agent.example:alice'
B = 'did:sage:web:agent.example:bob'
ALIASES = {'didDocument': {'id': A, 'verificationMethod': [], 'keyAgreement': []}, 'alsoKnownAs': ['did:example:display'], 'equivalentId': [B], 'canonicalId': 'did:example:display'}
POSITIVE = {'normal', 'matched-kem-2'}
CURRENT = {'local-kem-mismatch', 'revoke-init', 'revoke-resp', 'source-error', 'local-signing-mismatch'}
CLOSED = {site+'/'+name for site in ['outer', 'initiation'] for name in ALIASES}
CASES = POSITIVE | CURRENT | CLOSED
GROUPS = {'didp-04-peer-document-ignored', 'didp-04-received-alias'}
PACKAGE = 'github.com/sage-x-project/sage/pkg/agent/hpke'
PARENT = 'TestHandshakeKeyAuthorityBoundary010'
RUST_PREFIX = 'hpke::completion010::tests::key_authority::'
RUST_TESTS = {'handshake_key_authority_positive': POSITIVE, 'handshake_key_authority_current_source': CURRENT, 'handshake_key_authority_closed_fields': CLOSED}
MARKER = 'handshake-key-authority-witness '
COMMON_WIRE = set('context_id created did encoding expires id kid nonce recipient role signature version'.split())
INIT_KEYS = set('v task combiner ctx enc ephC initDid initKid kemKid nonce respDid respKid suite'.split())
TUPLE_KEYS = set('v combiner ctx initDid initKid kemKid kid respDid respKid suite th sid'.split())
COMMON_WITNESS = set('schema case scope request_b64 request_sha256 session_returned source_reads peer_document_parser operating_registry deployed_custody'.split())
POSITIVE_WITNESS = set('completion_b64 tuple application_request_b64 application_response_b64 application_request_opened application_response_opened request_replay_refused response_reuse_refused'.split())
SOURCES = ('scripts/core_key_authority_observation.py', 'scripts/core_key_authority_execution.py', 'scripts/check_core_key_authority_evidence.py', 'scripts/test_core_key_authority_observation.py', 'scripts/test_core_key_authority_execution.py', SUBJECT, FIXTURE, BASE+'/Cargo.lock', BASE+'/parser-calibrations.json', BASE+'/fixture-construction.md', 'docs/core-key-authority-inspection.md', '.github/workflows/core-key-authority-inspection.yml', 'scripts/current_spec_catalog.py', 'scripts/a2a_did_catalog.py', 'scripts/ingress_refusal_observation.py', 'scripts/owned_http_observation.py', 'scripts/a2a_card_observation.py')


def canonical(value):
    def ascii_value(v):
        require(type(v) in (dict, list, str, int, bool, type(None)), 'ASCII/integer fixture JSON only')
        if type(v) is str: require(v.isascii(), 'ASCII fixture string')
        elif type(v) is dict:
            for k, child in v.items():
                require(type(k) is str and k.isascii(), 'ASCII JSON member')
                ascii_value(child)
        elif type(v) is list:
            for child in v: ascii_value(child)
    ascii_value(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def closed(obj, keys, context):
    require(type(obj) is dict and set(obj) == set(keys), 'closed '+context)


def integer(value, expected, context):
    require(type(value) is int and value == expected, context+' integer')


def decode(value, length=None, maximum=32768):
    require(type(value) is str and len(value) <= maximum*2 and re.fullmatch('[A-Za-z0-9_-]+', value) is not None, 'bounded canonical base64url')
    try: raw = base64.urlsafe_b64decode(value+'='*((-len(value))%4))
    except (ValueError, base64.binascii.Error) as error: raise ValueError('invalid base64url') from error
    require(len(raw) <= maximum and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value and (length is None or len(raw) == length), 'base64url bytes/length')
    return raw


def document(raw, maximum=32768):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, 'bounded raw JSON')
    value = load(raw); canonical(value)
    return value


def uuid(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', value) is not None, 'canonical UUIDv4')


def public(seed, algorithm='ed25519'):
    cls = ed25519.Ed25519PrivateKey if algorithm == 'ed25519' else x25519.X25519PrivateKey
    return cls.from_private_bytes(bytes([seed])*32).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signature(value, field, domain, responder):
    raw = decode(value[field], 64)
    try: ed25519.Ed25519PublicKey.from_public_bytes(public(2 if responder else 1)).verify(raw, domain+canonical({k:v for k,v in value.items() if k != field}))
    except InvalidSignature as error: raise ValueError('public fixture signature') from error


def wire(raw, responder=False, session=False, extra=None):
    value = document(raw)
    keys = COMMON_WIRE | ({'data', 'message_id', 'request_hash', 'success'} if responder else {'payload'}) | ({'session_id'} if session else set()) | ({extra} if extra else set())
    closed(value, keys, 'wire envelope')
    require(value['version'] == '0.10.0' and value['role'] == ('responder' if responder else 'initiator') and value['did'] == (B if responder else A) and value['recipient'] == (A if responder else B) and value['kid'] == value['did']+'#signing-1' and value['encoding'] == ('session' if session else 'plain'), 'exact wire identity/role/key/encoding')
    integer(value['created'], 100, 'created'); integer(value['expires'], 400, 'expires')
    uuid(value['id']); uuid(value['context_id']); decode(value['nonce'], 16)
    if session: decode(value['session_id'], 16)
    if responder:
        uuid(value['message_id']); decode(value['request_hash'], 32)
        require(value['success'] is True, 'strict successful response')
    payload = decode(value['data' if responder else 'payload'])
    require(not session or len(payload) >= 36, 'session ciphertext framing only')
    signature(value, 'signature', b'sage-wire-response|0.10.0\n' if responder else b'sage-wire-request|0.10.0\n', responder)
    return value, payload


def initiation(payload, request, rotated, extra=None):
    inner = document(payload)
    closed(inner, INIT_KEYS | ({extra} if extra else set()), 'initiation')
    require(payload == canonical(inner), 'canonical initiation bytes')
    require(inner['v'] == '0.10.0' and inner['task'] == 'hpke/init@0.10.0' and inner['combiner'] == 'e2e-x25519-hkdf-v1' and inner['suite'] == 'hpke-base+x25519+hkdf-sha256', 'fixed handshake profile')
    require(inner['initDid'] == A and inner['respDid'] == B and inner['initKid'] == A+'#signing-1' and inner['respKid'] == B+'#signing-1' and inner['kemKid'] == B+('#kem-2' if rotated else '#kem-1') and inner['ctx'] == request['context_id'] and inner['nonce'] == request['nonce'], 'initiation bindings')
    decode(inner['enc'], 32); decode(inner['ephC'], 32)
    return inner


def correlation(response, request):
    require(response['message_id'] == request['id'] and response['context_id'] == request['context_id'] and decode(response['request_hash'], 32) == hashlib.sha256(canonical(request)).digest() and response['id'] != request['id'] and response['nonce'] != request['nonce'], 'signed response correlation')


def completion(w, request, init):
    reply, payload = wire(decode(w['completion_b64']), True)
    correlation(reply, request)
    done = document(payload); require(payload == canonical(done), 'canonical completion bytes'); closed(done, {'v', 'task', 'transcript', 'ackTagB64', 'sigB64'}, 'completion')
    require(done['v'] == '0.10.0' and done['task'] == 'hpke/complete@0.10.0', 'completion task')
    decode(done['ackTagB64'], 32); signature(done, 'sigB64', b'sage-hpke-complete|0.10.0\n', True)
    transcript = done['transcript']; closed(transcript, INIT_KEYS | {'ephS', 'kid'}, 'transcript')
    require(all(type(transcript[k]) is type(v) and transcript[k] == v for k,v in init.items()), 'all initiation transcript members')
    decode(transcript['ephS'], 32); uuid(transcript['kid'])
    tuple_ = w['tuple']; closed(tuple_, TUPLE_KEYS, 'authenticated tuple')
    require(all(tuple_[k] == transcript[k] for k in TUPLE_KEYS-{'th', 'sid'}), 'complete tuple members')
    th = hashlib.sha256(canonical(transcript)).digest()
    require(decode(tuple_['th'], 32) == th and decode(tuple_['sid'], 16) == hashlib.sha256(b'sage-session|0.10.0'+th).digest()[:16], 'independent public TH/SID derivation')
    req, _ = wire(decode(w['application_request_b64']), session=True)
    res, _ = wire(decode(w['application_response_b64']), responder=True, session=True)
    correlation(res, req)
    require(req['context_id'] == res['context_id'] == request['context_id'] and req['session_id'] == res['session_id'] == tuple_['sid'], 'application tuple binding')
    integer(w['application_request_opened'], 1, 'opened request'); integer(w['application_response_opened'], 1, 'opened response')
    require(w['request_replay_refused'] is True and w['response_reuse_refused'] is True, 'native replay/reuse refusal assertions')


def key(name, seed, algorithm='ed25519', state='accepted'):
    return {'name': name, 'alg': algorithm, 'material': public(seed, algorithm).hex(), 'state': state}


def snapshot(case, endpoint, did):
    rotated = case in {'matched-kem-2', 'local-kem-mismatch'} and did == B
    revoked = (case == 'revoke-init' and did == A or case == 'revoke-resp' and did == B) and endpoint == 'server'
    version = '3' if rotated or case in {'revoke-init', 'revoke-resp'} and endpoint == 'server' else '2'
    keys = [key('signing-1', 1 if did == A else 2, state='revoked' if revoked else 'accepted'), key('signing-2', 8 if did == A else 9)]
    if did == B:
        keys.insert(0, key('kem-1', 3, 'x25519', 'revoked' if rotated else 'accepted'))
        if rotated: keys.insert(1, key('kem-2', 7, 'x25519'))
    return {'source':'fixture-authority', 'registry':'web:agent.example', 'network':'local', 'did':did, 'version':version, 'state':'active', 'digest':sha(canonical(keys)), 'ready':True, 'validated':True, 'finalized':True, 'conflicting':False, 'acquired_ms':0, 'block_hash':'', 'keys_block_hash':'', 'keys':keys}


def source_order(case, language):
    if case in CLOSED: order = [('client', A), ('client', B), ('client', A)]
    elif case in {'revoke-init', 'source-error'}: order = [('client', A), ('client', B), ('server', A)]
    elif case in POSITIVE:
        order = [('client', A), ('client', B), ('server', A), ('server', B), ('client', A), ('client', B)]
        if language == 'rust': order += [('client', A), ('client', B), ('server', A), ('server', B), ('server', A), ('server', B), ('client', A), ('client', B), ('server', A), ('server', B)]
    else: order = [('client', A), ('client', B), ('server', A), ('server', B)]
    return order


def sources(w, language):
    case = w['case']; reads = w['source_reads']; order = source_order(case, language)
    require(type(reads) is list and len(reads) == len(order), 'exact Source read count/phase')
    for row, (endpoint, did) in zip(reads, order):
        expected = {'endpoint':endpoint, 'requested_did':did}
        if case == 'source-error' and endpoint == 'server': expected['error'] = 'source'
        else: expected['snapshot'] = snapshot(case, endpoint, did)
        require(canonical(row) == canonical(expected), 'authored complete Source/key/version/role/history observation')


def witness(w, language):
    require(language in {'go', 'rust'} and type(w) is dict and type(w.get('case')) is str and w['case'] in CASES, 'known witness identity')
    case = w['case']; good = case in POSITIVE
    keys = COMMON_WITNESS | ({'server_replay_entries'} if language == 'go' else {'replay_publications'}) | (POSITIVE_WITNESS if good else set())
    if good: keys |= {'handshake_server_replay_entries'} if language == 'go' else {'handshake_source_reads', 'handshake_replay_publications'}
    closed(w, keys, 'core witness')
    require(w['schema'] == 'sage-core-key-authority/1' and w['scope'] == 'PREVALIDATED_STATIC_SOURCE_MEMORY_UNIT' and w['peer_document_parser'] == 'NOT_EXPOSED' and w['operating_registry'] == w['deployed_custody'] == 'NOT_BOUND' and w['session_returned'] is good, 'bounded fixture scope/result')
    raw = decode(w['request_b64']); require(sha(raw) == w['request_sha256'], 'original raw request hash')
    site, name = case.split('/') if case in CLOSED else ('', None)
    request, payload = wire(raw, extra=name if site == 'outer' else None)
    inner = initiation(payload, request, case in {'matched-kem-2', 'local-kem-mismatch'}, name if site == 'initiation' else None)
    if name:
        actual = request[name] if site == 'outer' else document(inner[name].encode()) if type(inner[name]) is str else None
        require(canonical(actual) == canonical(ALIASES[name]), 'typed intended extra member only')
    sources(w, language)
    if language == 'go':
        integer(w['server_replay_entries'], 5 if good else 0, 'final server retained replay entries')
        if good: integer(w['handshake_server_replay_entries'], 3, 'handshake server replay entries')
    else:
        publications = [{'endpoint':'server', 'kind':'handshake', 'retained_entries':3, 'context':request['context_id']}, {'endpoint':'client', 'kind':'handshake', 'retained_entries':2, 'context':''}, {'endpoint':'server', 'kind':'record', 'retained_entries':5}, {'endpoint':'client', 'kind':'record', 'retained_entries':4}] if good else []
        require(canonical(w['replay_publications']) == canonical(publications), 'exact ordered successful replay publications')
        if good: require(canonical(w['handshake_source_reads']) == canonical(w['source_reads'][:6]) and canonical(w['handshake_replay_publications']) == canonical(publications[:2]), 'separate handshake/record phase prefixes')
    if good: completion(w, request, inner)
    return w


def go_witnesses(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 2097152 and raw.endswith(b'\n'), 'bounded complete test2json stream')
    names = {PARENT+'/'+case:case for case in CASES}; buffers = {}; found = {}; started = []; passed = []; package_pass = 0; package_start = 0; active = set()
    for line in raw.splitlines():
        require(package_pass == 0, 'no events after terminal Go package PASS')
        require(0 < len(line) <= 65536, 'bounded Go event line')
        e = load(line)
        require(type(e) is dict and e.get('Package') == PACKAGE and e.get('Action') in {'start','run','output','pass'} and e.get('Test', '') in {'',PARENT,*names}, 'exact Go package/action/test; no failure/skip')
        require(set(e) <= {'Time','Action','Package','Test','Elapsed','Output'} and ('Elapsed' not in e or type(e['Elapsed']) in (int,float) and 0 <= e['Elapsed'] <= 3600), 'standard Go event fields/finite elapsed; not signed fixture JSON')
        test = e.get('Test', '')
        if e['Action'] == 'start':
            require(test == '' and package_start == 0 and not active and not started, 'one initial Go package start'); package_start += 1
        elif e['Action'] == 'run':
            require(package_start == 1 and test in {PARENT,*names} and test not in started and (test == PARENT or PARENT in active), 'Go test begins once beneath active parent')
            started.append(test); active.add(test)
        if e['Action'] == 'pass':
            if test:
                require(test in active and (test != PARENT or active == {PARENT}), 'Go PASS follows RUN and all child terminals')
                passed.append(test); active.remove(test)
            else:
                require(package_start == 1 and not active, 'Go package terminal follows test terminals'); package_pass += 1
        if e['Action'] == 'output':
            require(package_start == 1 and (not test or test in active), 'Go output belongs to running test')
            text = e.get('Output'); require(type(text) is str and len(text.encode()) <= 4096, 'bounded Go output fragment')
            buffers[test] = buffers.get(test, '')+text; require(len(buffers[test].encode()) <= 131072, 'bounded attributed line')
            while '\n' in buffers[test]:
                line, buffers[test] = buffers[test].split('\n', 1)
                if MARKER in line:
                    require(test in names and line.count(MARKER) == 1 and names[test] not in found, 'unique correctly attributed Go witness')
                    w = document(line.split(MARKER, 1)[1].encode(), 131072)
                    require(w.get('case') == names[test], 'Go leaf/case linkage'); found[w['case']] = witness(w, 'go')
    require(not any(buffers.values()) and Counter(started) == Counter(passed) == Counter([PARENT,*names]) and package_pass == package_start == 1 and not active and set(found) == CASES, 'complete Go tests/witnesses exactly once')
    return found


def rust_witnesses(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 2097152 and raw.endswith(b'\n'), 'bounded complete Rust stdout')
    text = raw.decode(); current = None; started = []; finished = []; found = {}; summary = 0; header = 0
    start = re.compile(r'^test '+re.escape(RUST_PREFIX)+r'(handshake_key_authority_\w+) \.\.\. (.*)$')
    for line in text.splitlines():
        match = start.fullmatch(line)
        if match:
            require(current is None and match[1] in RUST_TESTS, 'exact serial Rust test boundary')
            current = match[1]; started.append(current); line = match[2]
        if line == 'running 3 tests': header += 1
        if line.startswith('test result: '):
            require(re.fullmatch(r'test result: ok\. 3 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s', line) is not None and current is None, 'complete Rust successful summary'); summary += 1
        if MARKER in line:
            require(current in RUST_TESTS and line.startswith(MARKER) and line.count(MARKER) == 1, 'attributed Rust witness')
            w = document(line[len(MARKER):].encode(), 131072)
            require(w.get('case') in RUST_TESTS[current] and w['case'] not in found, 'unique Rust test/case linkage'); found[w['case']] = witness(w, 'rust')
        elif line == 'ok':
            require(current is not None, 'Rust terminal belongs to test'); finished.append(current); current = None
        else: require(not line.startswith('test ') or line.startswith('test result: '), 'no extra Rust tests')
    require(current is None and Counter(started) == Counter(finished) == Counter(list(RUST_TESTS)) and set(found) == CASES and header == summary == 1 and 'FAILED' not in text, 'exact Rust tests and logical witnesses')
    return found


def subject(root=ROOT):
    raw = (root/SUBJECT).read_bytes(); require(sha(raw) == SUBJECT_SHA, 'core subject drift')
    value = load(raw); closed(value, {'schema','spec_revision','go','rust'}, 'paired core subject')
    require(value['schema'] == 'sage-core-key-authority-subject-v1' and value['spec_revision'] == SPEC_REVISION, 'adopted subject spec')
    for lang in ['go','rust']:
        selected = value[lang]
        closed(selected, {'revision','tree','module','critical_modules','sources','whole_sources'} if lang == 'go' else {'repository','revision','tree','sources','whole_sources','lock_path','lock_sha256'}, 'language acquisition subject')
        require(type(selected) is dict and re.fullmatch('[0-9a-f]{40}', selected['revision']) is not None and type(selected['sources']) is dict and all(type(p) is str and not Path(p).is_absolute() and '..' not in Path(p).parts and re.fullmatch('[0-9a-f]{64}', h) is not None for p,h in selected['sources'].items()), 'selected source identities')
        whole = selected['whole_sources']
        require(type(whole) is dict and len(whole) == (796 if lang == 'go' else 272) and all(type(p) is str and p.isascii() and not Path(p).is_absolute() and '..' not in Path(p).parts and '\n' not in p and re.fullmatch('[0-9a-f]{64}', h) is not None for p,h in whole.items()) and all(whole.get(p) == h for p,h in selected['sources'].items()), 'pinned complete acquisition source manifest')
    return value


def fixtures(root=ROOT):
    raw = (root/FIXTURE).read_bytes(); require(sha(raw) == FIXTURE_SHA, 'core fixture drift')
    value = load(raw); closed(value, {'schema','spec_revision','cases','mapping','scope'}, 'core fixture')
    require(value['schema'] == 'sage-core-key-authority-fixtures-v1' and value['spec_revision'] == SPEC_REVISION and value['cases'] == sorted(CASES) and set(value['mapping']) == GROUPS and all(v == sorted(CASES) for v in value['mapping'].values()) and value['scope'] == 'paired-fixed-memory-completion-units', 'paired all-cases fixture')
    return value


def assess(go, rust, root=ROOT):
    selected = subject(root); fixture = fixtures(root)
    for lang, rows in [('go',go),('rust',rust)]:
        require(type(rows) is dict and set(rows) <= CASES and all(k == w.get('case') and witness(w, lang) for k,w in rows.items()), 'typed independent language observations')
    complete = set(go) == set(rust) == CASES
    report = inventory(root)
    for row in report['cases']:
        row['status'] = 'PARTIAL' if complete and row['id'] in GROUPS else 'NOT_RUN'
        if row['id'] in GROUPS: row['coverage_notes'] = 'Paired core exact-key authority and closed handshake member controls; no peer-document input API or operating authority proof.'
    report.update(kind='paired-core-key-authority-observation', evidence_kind='reported-output', subject=selected, subject_manifest_sha256=SUBJECT_SHA, fixture_sha256=FIXTURE_SHA, go_observations=go, rust_observations=rust, status_counts=dict(Counter(c['status'] for c in report['cases'])), historical_results_merged=False, scope={'core_transport':'FIXED_MEMORY_UNIT_ONLY', 'source':'PREVALIDATED_STATIC_FIXTURE_ONLY', 'peer_document_parser':'NOT_EXPOSED', 'operating_registry':'NOT_BOUND', 'protected_custody_deployment':'NOT_BOUND', 'host_execution_guard':'NOT_BOUND', 'decryption':'ACTUAL_NATIVE_ASSERTIONS_NOT_INDEPENDENT_PYTHON_AEAD', 'full_conformance':'NOT_ESTABLISHED'})
    return report


def observer_sources(root=ROOT):
    return {path:sha((root/path).read_bytes()) for path in SOURCES}
