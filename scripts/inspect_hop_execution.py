"""Independently inspect native A-to-B-to-A execution using fixed inert requests."""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from itertools import product

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import inspect_hop_issuance as issuance
import inspect_mcp_consumer as root_consumer
from inspect_intent_issuance import canonical, require, RUST_LOCK
from inspect_public_mcp_host import ALICE, BOB, HEADER, LEDGER, decode, signed, strict_json
from inspect_root_capture_parity import NORMATIVE_REVISION, ROOT, UUID, check_source, sha

GO_REVISION = issuance.GO_REVISION
RUST_REVISION = issuance.RUST_REVISION
SOURCE_SHA256 = issuance.SOURCE_SHA256
LOCK = issuance.LOCK
LOCK_SHA256 = issuance.LOCK_SHA256
REPORT = ROOT / 'docs/evidence/hop-execution.json'
ADAPTERS = {'go': ROOT / 'adapters/hop-execution/go/main.go.txt',
            'rust': ROOT / 'adapters/hop-execution/rust/main.rs'}
ADAPTER_SHA256 = {
    "go": "7f28e2f273ec259c01fe0ec3a48425eff6179fa47739efd26f8ab750e82ae749",
    "rust": "8aad499b5aa4da700dac29f62932f590c86c813c02c9f21be306f568791e8a12"
}
CONFIGS = [(*langs, 'allowed') for langs in product(('go', 'rust'), repeat=3)] + [
    (*langs, scenario) for langs in [('go', 'rust', 'go'), ('rust', 'go', 'rust')]
    for scenario in ('policy-denied', 'measurement-denied', 'signing-denied', 'leaf-readiness-denied')]
SCOPE = {'native_hop_execution': 'LOCAL_NATIVE_HOP_EXECUTION_BOUND',
         'deployed_host': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED',
         'outer_handshake_oracle': 'NOT_RUN', 'registry': 'LOCAL_FIXTURE',
         'clock': 'LOCAL_SIMULATED_QUARANTINE', 'component': 'LOADED_INERT_FIXTURE',
         'key_custody': 'PUBLIC_FIXTURE_KEYS', 'leaf_context': 'PROTECTED_SHARED_FIXTURE',
         'effect': 'INERT_EXACT_READ', 'adk_integration': 'NOT_RUN'}


def identity(client, server, leaf, scenario):
    return f'{client}-to-{server}-to-{leaf}-{scenario}'


def manifest(root):
    return ('[package]\nname="mcp_consumer"\nversion="0.0.0"\nedition="2021"\nrust-version="1.88"\n'
            '[dependencies]\n' + f'sage_crypto_core={{path={json.dumps(str(root))}}}\n' +
            'serde_json="1.0"\nsha2="0.11"\nhex="0.4"\ned25519-dalek="2.2"\nx25519-dalek="2.0"\n')


def build(temp, roots):
    env = os.environ.copy()
    env.update(GOPROXY='off', GOFLAGS='-mod=mod', CARGO_NET_OFFLINE='true',
               GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    binaries = {}
    for lang in ('go', 'rust'):
        directory = temp / (lang + '-module'); directory.mkdir()
        if lang == 'go':
            (directory / 'main.go').write_bytes(ADAPTERS[lang].read_bytes())
            (directory / 'go.mod').write_text('module sage-inspector-mcp-consumer\n\ngo 1.26.0\n'
                'require github.com/sage-x-project/sage v0.0.0\n' +
                f'replace github.com/sage-x-project/sage => {json.dumps(str(roots[lang]))}\n')
            binaries[lang] = temp / 'go-consumer'
            command = ['go', 'build', '-o', str(binaries[lang]), '.']
        else:
            (directory / 'src').mkdir()
            (directory / 'src/main.rs').write_bytes(ADAPTERS[lang].read_bytes())
            (directory / 'Cargo.toml').write_text(manifest(roots[lang]))
            (directory / 'Cargo.lock').write_bytes(LOCK.read_bytes())
            binaries[lang] = temp / 'rust-target/debug/mcp_consumer'
            command = ['cargo', 'build', '--locked', '--offline', '--quiet']
        subprocess.run(command, cwd=directory, env=env, check=True, timeout=300)
    return binaries


def observe(client, server, leaf, scenario, binaries, directory):
    directory.mkdir()
    env = os.environ.copy()
    env.update(SAGE_CONSUMER_ROOT=str(directory), SAGE_CONSUMER_SCENARIO='allowed',
               SAGE_HOP_SCENARIO=scenario)
    workers = []
    try:
        for mode, language, filename in [('leaf', leaf, 'leaf-address'), ('server', server, 'address')]:
            env['SAGE_CONSUMER_MODE'] = mode
            worker = subprocess.Popen([str(binaries[language])], env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            workers.append(worker)
            end = time.monotonic() + 8
            while True:
                if worker.poll() is not None:
                    output, _ = worker.communicate()
                    raise ValueError('bounded ' + mode + ' startup: ' + output.decode(errors='replace')[:2500])
                require(time.monotonic() < end, 'bounded ' + mode + ' startup')
                address = directory / filename
                if address.exists():
                    value = address.read_text()
                    if re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', value) and 1 <= int(value.rsplit(':', 1)[1]) <= 65535:
                        break
                time.sleep(.01)
        env['SAGE_CONSUMER_MODE'] = 'client'
        done = subprocess.run([str(binaries[client])], env=env, capture_output=True, timeout=20)
        require(done.returncode == 0 and done.stdout == b'EXTERNAL_MCP_CONSUMER\n',
                'root client actually executed: ' + done.stderr.decode(errors='replace')[:2500])
        for worker in workers:
            output, _ = worker.communicate(timeout=8)
            require(worker.returncode == 0 and output == b'EXTERNAL_MCP_CONSUMER\n',
                    'bounded worker executed: ' + output.decode(errors='replace')[:2500])
        return {'id': identity(client, server, leaf, scenario),
                **{mode: strict_json((directory / (mode + '.json')).read_bytes())
                   for mode in ('client', 'server', 'leaf')}}
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill(); worker.communicate(timeout=3)



# Retained root rules with explicit expectations for the forwarding result.
def root_events(journal):
    require(journal.startswith(HEADER) and journal.endswith(b'\n'), 'root journal framing')
    rows = [strict_json(line) for line in journal[len(HEADER):].splitlines()]
    require(1 <= len(rows) <= 52 and all(type(row) is dict and set(row) ==
            {'kind', 'id', 'at', 'intent_hex', 'result_hex'} and type(row['at']) is int for row in rows),
            'closed bounded root events')
    return rows


def check_root_case(case, result_created, result_output):
    require(type(case) is dict and set(case) == {'id', 'client', 'server'}, 'closed observation')
    client, server = case['client'], case['server']
    require(type(client) is dict and set(client) == {'mode', 'status', 'effects', 'ledger_hex',
            'journal_hex', 'fence_hex', 'before_transfer_hex', 'sign_calls', 'issuance_body_hex',
            'prepare_denied', 'stage', 'owned_capture_digest'} and
            type(server) is dict and set(server) == {'mode', 'status', 'effects', 'ledger_hex', 'prepare_denied'},
            'closed external consumer records')
    scenario = 'allowed'
    allowed = True
    expected_stage = {'allowed': 'completed', 'policy-denied': 'authorizing',
                      'measurement-denied': 'authorizing', 'capture-denied': 'opening',
                      'readiness-denied': '', 'signing-denied': 'issuing'}[scenario]
    require(client['prepare_denied'] is False and
            server['prepare_denied'] is (scenario == 'readiness-denied') and
            client['stage'] == expected_stage, 'specified rejection boundary actually reached')
    original = b'changed root' if scenario == 'capture-denied' else b'trusted root input'
    capture = sha(b'sage-original|0.10.0\0' + (1).to_bytes(4, 'big') +
                  len(original).to_bytes(8, 'big') + original) if scenario in ('allowed', 'capture-denied') else ''
    require(client['owned_capture_digest'] == capture, 'independent capture at owned entry')
    require(client['mode'] == 'client' and server['mode'] == 'server' and
            client['status'] == ('completed' if allowed else 'denied') and server['status'] == 'completed' and
            type(client['effects']) is int and client['effects'] == 0 and
            type(server['effects']) is int and server['effects'] == int(allowed) and
            decode(client['ledger_hex']) == LEDGER, 'measured effect and denial')
    journal, before, fence, body = (decode(client[k]) for k in
            ('journal_hex', 'before_transfer_hex', 'fence_hex', 'issuance_body_hex'))
    signs = client['sign_calls']
    require(type(signs) is int and signs == int(scenario in ('allowed', 'capture-denied', 'signing-denied')),
            'single protected signing attempt')
    if not signs:
        require(not journal and not before and not fence and not body and
                decode(server['ledger_hex']) == LEDGER, 'rejection before issuance and effect')
        return None
    intent = strict_json(body)
    require(body == canonical(intent), 'canonical issuance body')
    issued_identity = root_consumer.check_intent(intent)
    require(fence == root_consumer.FENCE + sha(body).encode() + b'\n', 'exact durable fence before signer')
    if scenario == 'signing-denied':
        require(not journal and not before and decode(server['ledger_hex']) == LEDGER,
                'failed signing retains fence without journal or effect')
        return issued_identity
    before_rows = root_events(before)
    require(len(before_rows) == 1, 'transfer before any transport event')
    raw = decode(before_rows[0]['intent_hex'])
    require(before_rows[0] == {'kind': 'open', 'id': '', 'at': 0, 'intent_hex': raw.hex(), 'result_hex': ''},
            'one original issued journal')
    require(canonical(signed(raw, 'intent', 1)) == body, 'snapshot preserves exact signed intent')
    require(journal.startswith(before), 'same append-only journal after ownership transfer')
    if scenario == 'capture-denied':
        require(journal == before and decode(server['ledger_hex']) == LEDGER,
                'independent capture mismatch denied before transport and effect')
        return issued_identity
    rows = root_events(journal)
    calls = rows[1:-1]
    require(calls and len(calls) % 2 == 0 and len(calls) <= 50, 'bounded complete handoffs')
    seen = set()
    for index in range(0, len(calls), 2):
        sent, closed = calls[index:index + 2]
        ident = sent['id']
        require(type(ident) is str and UUID.fullmatch(ident) is not None and ident not in seen,
                'fresh outer attempt identity')
        seen.add(ident)
        require(sent == {'kind': 'send', 'id': ident, 'at': 461000 + 1000 * (index // 2),
                         'intent_hex': '', 'result_hex': ''} and
                closed == {'kind': 'close', 'id': ident, 'at': 0, 'intent_hex': '', 'result_hex': ''},
                'reopen delay, retry cadence and identity consumption')
    terminal = rows[-1]
    result_raw = decode(terminal['result_hex'])
    require(terminal == {'kind': 'terminal', 'id': calls[-1]['id'], 'at': 0,
                         'intent_hex': '', 'result_hex': result_raw.hex()}, 'one terminal consumption')
    result = signed(result_raw, 'result', 2)
    require(canonical(result) == canonical({'version': '0.10.0', 'request_id': intent['request_id'],
            'call_id': intent['call_id'], 'issuer': BOB, 'recipient': ALICE,
            'created': result_created, 'expires': result_created + 300, 'keyid': BOB + '#signing-1', 'alg': 'ed25519',
            'intent_digest': sha(raw), 'status': 'completed', 'output': result_output}),
            'independent signed result binding')
    ledger = decode(server['ledger_hex'])
    require(ledger.startswith(LEDGER) and ledger.endswith(b'\n'), 'server ledger framing')
    entries = [strict_json(line) for line in ledger[len(LEDGER):].splitlines()]
    expected = {'issuer': ALICE, 'recipient': BOB, 'call_id': intent['call_id'],
                'nonce': intent['nonce'], 'expires': 760, 'intent_hex': raw.hex()}
    require(canonical(entries) == canonical([dict(expected, state=state,
            result_hex=result_raw.hex() if state == 'COMPLETED' else '')
            for state in ('RESERVED', 'EXECUTING', 'COMPLETED')]),
            'one durable reservation, execution and exact result')
    return issued_identity


def check_child_issuance(case, scenario, root_identity):
    child = case['server']['child']
    parent_rows = root_events(decode(case['client']['journal_hex']))
    incoming = decode(child['incoming_hex'])
    require(incoming == decode(parent_rows[0]['intent_hex']), 'exact admitted inbound bytes')
    parent = signed(incoming, 'intent', 1)
    body, fence, journal, raw = (decode(child[k]) for k in
        ('issuance_body_hex', 'fence_hex', 'journal_hex', 'signed_intent_hex'))
    count = child['sign_calls']
    require(type(count) is int and count == int(scenario in ('allowed', 'signing-denied', 'leaf-readiness-denied')),
            'one child protected signing attempt')
    if not count:
        require(not body and not fence and not journal and not raw and
                child['token_reuse_denied'] is None, 'own denial before signing or Client creation')
        return root_identity, None
    intent = strict_json(body)
    require(type(intent) is dict and body == canonical(intent), 'canonical child body')
    call, nonce = intent.get('call_id'), intent.get('nonce')
    require(type(call) is str and UUID.fullmatch(call) is not None and call != parent['call_id'] and
            type(nonce) is str and re.fullmatch('[A-Za-z0-9_-]{22}', nonce) is not None,
            'fresh child identity')
    decoded = base64.urlsafe_b64decode(nonce + '==')
    require(len(decoded) == 16 and base64.urlsafe_b64encode(decoded).rstrip(b'=').decode() == nonce,
            'canonical child nonce')
    manifest = {'version': '0.10.0', 'files': [{'path': 'component.bin',
                'sha256': sha(b'inert-exact-read-v1')}]}
    policy = {'version': '0.10.0', 'issuer': BOB,
              'epoch': '00000000-0000-4000-8000-000000000012',
              'engine': 'external-hop-fixture/1', 'artifacts': manifest}
    expected = {'version': '0.10.0', 'profile': 'sage-execution-guard',
                'request_id': '00000000-0000-4000-8000-000000000011',
                'call_id': call, 'parent_call_id': parent['call_id'], 'issuer': BOB, 'recipient': ALICE,
                'tool': 'read', 'arguments': {'path': 'public.txt'},
                'original_digest': sha(b'sage-original|0.10.0\0' + (1).to_bytes(4, 'big') +
                                       len(incoming).to_bytes(8, 'big') + incoming),
                'policy_digest': sha(b'sage-policy|0.10.0\0' + canonical(policy)),
                'manifest_digest': sha(canonical(manifest)), 'created': 460, 'expires': 760,
                'nonce': nonce, 'keyid': BOB + '#signing-1', 'alg': 'ed25519'}
    require(canonical(intent) == canonical(expected), 'independent child capture, parent and own policy')
    require(fence == root_consumer.FENCE + sha(body).encode() + b'\n', 'child fence before signer')
    require(child['token_reuse_denied'] is True, 'one-use child approval')
    if scenario == 'signing-denied':
        require(not journal and not raw, 'failed child signing retains fence without Client')
        return root_identity, (call, nonce)
    require(canonical(signed(raw, 'intent', 2)) == body, 'own child Ed25519 proof')
    rows = root_consumer.events(decode(child['before_transfer_hex']))
    require(rows == [{'kind': 'open', 'id': '', 'at': 0, 'intent_hex': raw.hex(), 'result_hex': ''}],
            'child transfer starts from its original issued journal')
    return root_identity, (call, nonce)



def urlbytes(value, length=None):
    require(type(value) is str and bool(re.fullmatch('[A-Za-z0-9_-]+', value)), 'base64url shape')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value and
            (length is None or len(raw) == length), 'canonical base64url length')
    return raw


def check_bootstrap(record):
    require(type(record) is dict and set(record) == {prefix + suffix for prefix in ('root', 'child')
            for suffix in ('_request_hex', '_response_hex', '_replay_hex')}, 'closed bootstrap observation')
    identities = set()
    for prefix, sender, recipient, seed in [('root', ALICE, BOB, 1), ('child', BOB, ALICE, 2)]:
        pair = []
        for role, domain, own, peer, key in [('request', 'request', sender, recipient, seed),
                                           ('response', 'response', recipient, sender, 3 - seed)]:
            raw = decode(record[prefix + '_' + role + '_hex'])
            value = strict_json(raw)
            keys = {'version', 'id', 'did', 'recipient', 'kid', 'created', 'expires', 'nonce',
                    'encoding', 'context_id', 'role', 'signature'}
            keys |= {'payload'} if role == 'request' else {'data', 'message_id', 'request_hash', 'success'}
            require(type(value) is dict and set(value) == keys and raw == canonical(value),
                    'closed canonical bootstrap wire')
            unsigned = dict(value); proof = urlbytes(unsigned.pop('signature'), 64)
            Ed25519PrivateKey.from_private_bytes(bytes([key]) * 32).public_key().verify(
                proof, ('sage-wire-' + domain + '|0.10.0\n').encode() + canonical(unsigned))
            require(value['version'] == '0.10.0' and value['did'] == own and
                    value['recipient'] == peer and value['kid'] == own + '#signing-1' and
                    type(value['created']) is int and value['created'] == 460 and
                    type(value['expires']) is int and value['expires'] == 760 and
                    value['encoding'] == 'plain' and
                    value['role'] == ('initiator' if role == 'request' else 'responder'),
                    'bootstrap signing role and quarantine clock')
            require(type(value['id']) is str and UUID.fullmatch(value['id']) and
                    type(value['context_id']) is str and UUID.fullmatch(value['context_id']),
                    'bootstrap identities')
            nonce = urlbytes(value['nonce'], 16)
            require(value['id'] not in identities and nonce not in identities, 'fresh bootstrap identities')
            identities.update((value['id'], nonce))
            nested = urlbytes(value['payload' if role == 'request' else 'data'])
            require(nested == canonical(strict_json(nested)), 'canonical authenticated bootstrap payload')
            pair.append(value)
        request, response = pair
        require(response['success'] is True and response['message_id'] == request['id'] and
                response['context_id'] == request['context_id'] and
                urlbytes(response['request_hash'], 32).hex() == sha(canonical(request)),
                'bootstrap response binds authenticated request')
        admitted = request if prefix == 'root' else response
        replay = decode(record[prefix + '_replay_hex'])
        header = b'sage-replay-denials|0.10.0\n'
        require(replay.startswith(header) and replay.endswith(b'\n'), 'bootstrap replay framing')
        rows = [strict_json(row) for row in replay[len(header):].splitlines()]
        require(canonical(rows) == canonical([{'at': 460, 'sender': admitted['did'],
                'recipient': admitted['recipient'], 'id': admitted['id'], 'nonce': admitted['nonce'],
                'context': admitted['context_id'] if prefix == 'root' else '', 'expires': 760}]),
                'recovered replay comes from actual signed bootstrap exchange')


def check_case(case, scenario):
    require(type(case) is dict and set(case) == {'id', 'client', 'server', 'leaf'}, 'closed hop observation')
    client, server, leaf = (case[k] for k in ('client', 'server', 'leaf'))
    require(type(server) is dict and set(server) == {'mode', 'status', 'effects', 'ledger_hex',
            'prepare_denied', 'child', 'bootstrap'}, 'closed middle observation')
    child = server['child']
    require(type(child) is dict and set(child) == {'status', 'stage', 'sign_calls', 'issuance_body_hex',
            'incoming_hex', 'journal_hex', 'fence_hex', 'signed_intent_hex', 'token_reuse_denied',
            'parent_after_finish_denied', 'before_transfer_hex', 'ticks', 'delivery_count',
            'delivery_output_hex', 'connection_status'}, 'closed child observation')
    require(type(client) is dict and 'consumed_output_hex' in client, 'root native output observation')
    require(type(leaf) is dict and set(leaf) == {'mode', 'status', 'effects', 'ledger_hex',
            'prepare_denied', 'connections', 'observed_parent_hex'}, 'closed leaf observation')
    allowed = scenario == 'allowed'
    require(child['status'] == ('completed' if allowed else 'denied') and child['stage'] ==
            {'allowed': 'completed', 'policy-denied': 'authorizing', 'measurement-denied': 'authorizing',
             'signing-denied': 'issuing', 'leaf-readiness-denied': 'connecting'}[scenario],
            'own child boundary actually reached')
    require(child['parent_after_finish_denied'] is True, 'finished parent loses authority')
    ticks, delivered = child['ticks'], child['delivery_count']
    require(type(ticks) is int and (1 <= ticks <= 10 if allowed else ticks == 0) and
            type(delivered) is int and delivered == int(allowed), 'bounded child progress and one delivery')
    require(child['connection_status'] == ('COMPLETED' if allowed else
            'DENIED' if scenario == 'leaf-readiness-denied' else 'NOT_ATTEMPTED'), 'child connection boundary')
    output = {'child_status': 'completed' if allowed else 'denied', 'output': {'ok': True} if allowed else None}
    require(decode(client['consumed_output_hex']) == canonical(output), 'root actually consumes child outcome')
    root = copy.deepcopy(case); del root['leaf']
    del root['server']['child']; del root['server']['bootstrap']; del root['client']['consumed_output_hex']
    root_identity = check_root_case(root, 460 + ticks, output)
    check_bootstrap(server['bootstrap'])
    identities = check_child_issuance(case, scenario, root_identity)
    journal, before = (decode(child[k]) for k in ('journal_hex', 'before_transfer_hex'))
    require(leaf['mode'] == 'leaf' and leaf['status'] == 'stopped' and
            type(leaf['effects']) is int and leaf['effects'] == int(allowed) and
            type(leaf['connections']) is int and leaf['connections'] == int(allowed or scenario == 'leaf-readiness-denied') and
            leaf['prepare_denied'] is (scenario == 'leaf-readiness-denied'), 'measured leaf effect and admission')
    if not allowed:
        require(decode(child['delivery_output_hex']) == b'' and decode(leaf['observed_parent_hex']) == b'' and
                decode(leaf['ledger_hex']) == LEDGER and
                journal == before and (bool(before) is (scenario == 'leaf-readiness-denied')),
                'child refusal before reservation or terminal delivery')
        return identities
    incoming = decode(child['incoming_hex'])
    require(decode(leaf['observed_parent_hex']) == incoming, 'leaf binds exact shared admitted parent fixture')
    raw = decode(child['signed_intent_hex']); intent = signed(raw, 'intent', 2)
    require(journal.startswith(before), 'child same append-only journal after handoff')
    rows = root_consumer.events(journal); attempts = rows[1:-1]
    require(len(attempts) == 2 * ticks, 'child cadence matches measured clock advances')
    seen = {row['id'] for row in root_events(decode(client['journal_hex']))[1:]}
    for index in range(0, len(attempts), 2):
        sent, closed = attempts[index:index + 2]; ident = sent['id']
        require(type(ident) is str and UUID.fullmatch(ident) and ident not in seen, 'fresh child outer identity')
        seen.add(ident)
        require(sent == {'kind': 'send', 'id': ident, 'at': 461000 + 1000 * (index // 2), 'intent_hex': '', 'result_hex': ''} and
                closed == {'kind': 'close', 'id': ident, 'at': 0, 'intent_hex': '', 'result_hex': ''},
                'child complete bounded handoffs')
    terminal = rows[-1]; result_raw = decode(terminal['result_hex'])
    require(terminal == {'kind': 'terminal', 'id': attempts[-1]['id'], 'at': 0,
                         'intent_hex': '', 'result_hex': result_raw.hex()}, 'child one terminal consumption')
    result = signed(result_raw, 'result', 1)
    require(canonical(result) == canonical({'version': '0.10.0', 'request_id': intent['request_id'],
            'call_id': intent['call_id'], 'issuer': ALICE, 'recipient': BOB,
            'created': 460, 'expires': 760, 'keyid': ALICE + '#signing-1', 'alg': 'ed25519',
            'intent_digest': sha(raw), 'status': 'completed', 'output': {'ok': True}}) and
            decode(child['delivery_output_hex']) == canonical({'ok': True}), 'independent child result and actual consumption')
    ledger = decode(leaf['ledger_hex'])
    require(ledger.startswith(LEDGER) and ledger.endswith(b'\n'), 'leaf ledger framing')
    entries = [strict_json(line) for line in ledger[len(LEDGER):].splitlines()]
    expected = {'issuer': BOB, 'recipient': ALICE, 'call_id': intent['call_id'], 'nonce': intent['nonce'],
                'expires': 760, 'intent_hex': raw.hex()}
    require(canonical(entries) == canonical([dict(expected, state=state,
            result_hex=result_raw.hex() if state == 'COMPLETED' else '')
            for state in ('RESERVED', 'EXECUTING', 'COMPLETED')]), 'one leaf reservation, execution and signed result')
    return identities


def check_inputs():
    root_consumer.check_inputs()
    require(sha(LOCK.read_bytes()) == LOCK_SHA256, 'pinned consumer lock')
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned core lock')
    require({k: sha(p.read_bytes()) for k, p in ADAPTERS.items()} == ADAPTER_SHA256,
            'hop execution adapter source drift')


def sources_at(roots):
    for lang, root in roots.items():
        check_source(root, GO_REVISION if lang == 'go' else RUST_REVISION)
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
                cwd=root, text=True).strip(), 'untracked core build inputs')
    hashes = {lang: {name: sha((root / name).read_bytes()) for name in SOURCE_SHA256[lang]}
              for lang, root in roots.items()}
    require(hashes == SOURCE_SHA256, 'core source drift')
    return hashes


def inspect(go_root, rust_root):
    check_inputs()
    roots = {'go': check_source(go_root, GO_REVISION), 'rust': check_source(rust_root, RUST_REVISION)}
    sources = sources_at(roots)
    with tempfile.TemporaryDirectory(prefix='sage-hop-execution-') as directory:
        temp = Path(directory)
        binaries = build(temp, roots)
        cases = [observe(c, s, leaf, scenario, binaries, temp / identity(c, s, leaf, scenario))
                 for c, s, leaf, scenario in CONFIGS]
        sources_at(roots); check_inputs()
    return {'schema_version': 1, 'kind': 'native-hop-execution-observation', 'protocol_version': '0.10.0',
            'normative_source_revision': NORMATIVE_REVISION, 'go_revision': GO_REVISION,
            'rust_revision': RUST_REVISION, 'source_sha256': sources,
            'adapter_sha256': ADAPTER_SHA256.copy(), 'consumer_lock_sha256': LOCK_SHA256,
            'compiler_status': 'EXTERNAL_PUBLIC_CONSUMERS_BUILT',
            'status': 'LOCAL_NATIVE_HOP_EXECUTION_BOUND', 'scope': SCOPE.copy(), 'cases': cases}


def check_report(report):
    check_inputs()
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'go_revision', 'rust_revision', 'source_sha256',
            'adapter_sha256', 'consumer_lock_sha256', 'compiler_status', 'status', 'scope', 'cases'},
            'closed hop report')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'native-hop-execution-observation' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['go_revision'] == GO_REVISION and
            report['rust_revision'] == RUST_REVISION and report['source_sha256'] == SOURCE_SHA256 and
            report['adapter_sha256'] == ADAPTER_SHA256 and report['consumer_lock_sha256'] == LOCK_SHA256 and
            report['compiler_status'] == 'EXTERNAL_PUBLIC_CONSUMERS_BUILT' and
            report['status'] == 'LOCAL_NATIVE_HOP_EXECUTION_BOUND' and report['scope'] == SCOPE,
            'hop scope and provenance')
    require(type(report['cases']) is list and all(type(c) is dict for c in report['cases']) and
            [case.get('id') for case in report['cases']] == [identity(*config) for config in CONFIGS],
            'eight allowed combinations and eight ordered refusal observations')
    calls, nonces = set(), set()
    for case, (_, _, _, scenario) in zip(report['cases'], CONFIGS):
        for ident in check_case(case, scenario):
            if ident:
                call, nonce = ident
                require(call not in calls and nonce not in nonces, 'distinct root and child issuance')
                calls.add(call); nonces.add(nonce)
    return len(report['cases'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path); parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--report', type=Path, default=REPORT); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root) or args.output and not args.go_root:
        parser.error('supply both exact core roots; output requires execution')
    report = inspect(args.go_root, args.rust_root) if args.go_root else strict_json(args.report.read_bytes())
    count = check_report(report)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': count, 'status': report['status'],
                      'native_hop_execution': report['scope']['native_hop_execution']}))


if __name__ == '__main__':
    main()
