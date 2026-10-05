"""Independently inspect protected issuance through external native MCP consumers.

Only fixed inert localhost root requests are executed. Fixture registry readiness,
clock advancement and component binding do not certify a deployed host or loader.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from inspect_intent_issuance import RUST_LOCK, canonical, require
from inspect_public_mcp_host import ALICE, BOB, HEADER, LEDGER, decode, signed, strict_json
from inspect_root_capture_parity import NORMATIVE_REVISION, ROOT, UUID, check_source, sha

GO_REVISION = '11b1cd91691de99fdbd734db78dc6755c187b2e9'
RUST_REVISION = 'cf3edb86a04e8ca0141b252c85e002c1f49bf9eb'
REPORT = ROOT / 'docs/evidence/mcp-consumer.json'
LOCK = ROOT / 'verification/0.10.0/mcp-consumer/Cargo.lock'
LOCK_SHA256 = 'bf34ee27c6c23774e9f656df345ecb9f7cbdb2c71891922cf7217fce05250f49'
ADAPTERS = {'go': ROOT / 'adapters/mcp-consumer/go/main.go.txt',
            'rust': ROOT / 'adapters/mcp-consumer/rust/main.rs'}
ADAPTER_SHA256 = {
    "go": "1da3adb1bdfcba2686950df75142ae688f1855ad065164b5b9860ed963fc8e8c",
    "rust": "ffb3b109a7e143a6a7f19197dfa0d41ee2cd5cae6ad4cd5725f6435c0c8a7d0b"
}
SOURCE_SHA256 = {
    "go": {
        "go.mod": "c23a68976d75c786fff32e062e6c5b670a6a3959ec3580ff0b2a09cbf1e45536",
        "go.sum": "eef9fb09a9ef609fc2d7146d4a7970eb05ca34c3bf4461a8d138dace063836d8",
        "pkg/agent/guard010/client.go": "c5101f228c2e0ba17aacbc79f5010c6b5697b450075bf3e070d4d6368b304676",
        "pkg/agent/guard010/commitment.go": "74ce20c5097ada6c3ed1b732452daf40ca8a4bac5fa14fc578f78286334c0486",
        "pkg/agent/guard010/dispatch.go": "52b1d9f126ccb76a8af465ca20698690ff2431a624a6bd49a8a8a2bbdd6eefcd",
        "pkg/agent/guard010/issuance.go": "e0537b5418eca3e10bb98db5858636e659811ba759ec8d698199ee6f5b555032",
        "pkg/agent/guard010/json.go": "d92529d21b23adb43436d890ce7c3829a73ebfcdb8cc528108cc78de94e6e442",
        "pkg/agent/guard010/ledger.go": "957e27e791ac34d2e7a20ae4d7262a8677806317e67c71fc19b110314409019b",
        "pkg/agent/guard010/mcp.go": "96bec863f4e18aacaae16f18eecfe5bbb75e28a7a175556c054dfd40c8db4094",
        "pkg/agent/guard010/mcp_admission.go": "fd4df3e247c1278445e925b4f57fae3870cb1f6466cb1752ad845ed7fddcc7d9",
        "pkg/agent/guard010/mcp_connection.go": "52a18eefa3218304d8d3ec2b36962ab86572b839aa9bf90db7a2a04b894f0dff",
        "pkg/agent/guard010/mcp_host.go": "3107a4ca72cdc85bed8876cd90f7c7ce5caf863175c8424847ca0c35a5c00217",
        "pkg/agent/guard010/mcp_owned_client.go": "600a9d7ee31bb17d730ab016d32069998a8b1bf73d1a5a257ca0828520390619",
        "pkg/agent/guard010/mcp_owner.go": "f4d376555edfca44b799cc52b3b9a08e9ed6940a4fc227bb9e38f15dc7a1ba37",
        "pkg/agent/guard010/mcp_protected_reply.go": "781c2273d4775bf4615d2b6a6828d6210da5931a18781c4732b99d4819f89303",
        "pkg/agent/guard010/mcp_public.go": "f3c495302c730349dd89f461b4a19236a36b734a8c60ffdf0c2caa6d0a47bf6d",
        "pkg/agent/guard010/mcp_root_capture.go": "abfb4f152ce1bb0ed7535418c61d0c1e41004402485a39c9d6216dd7b8350399",
        "pkg/agent/guard010/mcp_rpc.go": "8e48f15940001e59a4e61d55b9404f65d5a2bf0836634780fb1f6fcd5147c315",
        "pkg/agent/guard010/mcp_session.go": "d2cf452012be1825c1618f1f762ca34fdbab4055312b3c741bf535048089113b",
        "pkg/agent/guard010/mcp_setup.go": "0cfac5cf2180bb8cec1de7f4171db3645bcd4c93fc5b1f688ab9b58a381708e2",
        "pkg/agent/guard010/mcp_setup_session.go": "3ab9fac40fd087e7f882bab0971a94197ae6305b2188cf3fc9252df7a57e2e97",
        "pkg/agent/guard010/mcp_stream.go": "5cbfa5d1330fb2d2ca8af327fdb21d61f165ffb8c0325e26fe479eb3ab41f452",
        "pkg/agent/guard010/registry.go": "d6ac914001f74e61406dc64cf1d94dce35a2c6a457894bd97e071e8f4c724a47",
        "pkg/agent/guard010/results.go": "5e7e8d60d5baa4e6db2a150fdcc4502900653b52c4a741e7a8f126925a4b8c65",
        "pkg/agent/guard010/verify.go": "04b1c09f18a54c004d31bbdde1db95af757e815877344981b1b50797c189df60"
    },
    "rust": {
        "Cargo.lock": "04099b5ee7c1320fb249112b1fba052aad1a433cc26d60e4537db108b69d6a38",
        "Cargo.toml": "8dfe7286e8eae2718cfce19113ab40364cd8ed6a3bc6a0b9f78d4caaf096e36a",
        "src/guard010/client.rs": "a93a2cbc94b79f4f5d4cc4082364567cb216bb0cbec5828c0fe2110c21d5aca8",
        "src/guard010/dispatch.rs": "038875d6bd463b34d9d3c2526ff3fdb8fad7f356f963dd0ab9deb6dee38501ac",
        "src/guard010/issuance.rs": "7bd94da4b694ff9a3793e432323362df8a02992f8734e0e514ff6b62692d1cb4",
        "src/guard010/ledger.rs": "53bcb18977c27e2d312ed90054e0eabde31aedf5a95819f07f0112f4fddba7f5",
        "src/guard010/mcp.rs": "53661a5025a4e5360ab8eaf2278d547950177623a5dfe0cc4927092270a5b70e",
        "src/guard010/mcp_lifecycle.rs": "134c06370151151428ce5d552ad8830a381c3c2cdfecf5337bd29189d48fd1c1",
        "src/guard010/mcp_owned.rs": "f309c800e0e929f84101dfb61af639617dae79722046cf45c95295e0a36f7cf8",
        "src/guard010/mcp_public.rs": "cf49f22182f5bd6787a17a281e561bb7130722ff144fae33eb700442f33a14ff",
        "src/guard010/mcp_rpc.rs": "c8704132740ee3e51b6e213fba8042d607884521077132d7d7dcb039c4863de8",
        "src/guard010/mcp_session.rs": "e8a89743769367e60dcb73295ac75e4993c478602cdde63d73704a0f60491da7",
        "src/guard010/mcp_setup.rs": "b00a53c17d4bda3a0f4d76efca41e10a6066d18250a272a2f9a9dc1d322a4eac",
        "src/guard010/mcp_transport.rs": "dd2c9aca02b96d4cfe31100e469df51296740eb13c5a2d4749b1a85c22ef3e45",
        "src/guard010/mod.rs": "a43263e9acada1a96e90723e0e94df7bb01ef812c2ac1355c74306ad136fc268",
        "src/guard010/registry.rs": "4490cd2a5567485e5cba7ddcff700d159ee63623ab06eff985fe45fb6b572c26"
    }
}
DIRECTIONS = [('go', 'go'), ('rust', 'rust'), ('go', 'rust'), ('rust', 'go')]
DENIALS = ('policy-denied', 'measurement-denied', 'capture-denied', 'readiness-denied', 'signing-denied')
CONFIGS = [(c, s, 'allowed') for c, s in DIRECTIONS] + [
    (c, s, scenario) for c, s in [('go', 'rust'), ('rust', 'go')] for scenario in DENIALS]
SCOPE = {'issuer_consumer_binding': 'ROOT_EXTERNAL_CONSUMER_BOUND',
         'deployed_host': 'NOT_RUN', 'independent_hop_execution': 'NOT_RUN',
         'outer_handshake_oracle': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED',
         'registry': 'LOCAL_FIXTURE', 'clock': 'LOCAL_SIMULATED_QUARANTINE',
         'component': 'LOADED_INERT_FIXTURE', 'key_custody': 'PUBLIC_FIXTURE_KEYS',
         'effect': 'INERT_EXACT_READ'}
FENCE = b'sage-intent-issuance|0.10.0\n'


def identity(client, server, scenario):
    return f'{client}-to-{server}-{scenario}'


def check_intent(intent):
    require(type(intent) is dict, 'intent object')
    call, nonce = intent.get('call_id'), intent.get('nonce')
    require(type(call) is str and UUID.fullmatch(call) is not None,
            'fresh issued call identity')
    require(type(nonce) is str and re.fullmatch('[A-Za-z0-9_-]{22}', nonce) is not None,
            'issued nonce shape')
    raw_nonce = base64.urlsafe_b64decode(nonce + '==')
    require(len(raw_nonce) == 16 and base64.urlsafe_b64encode(raw_nonce).rstrip(b'=').decode() == nonce,
            'canonical issued nonce')
    manifest = {'version': '0.10.0', 'files': [{'path': 'component.bin', 'sha256': sha(b'inert-exact-read-v1')}]}
    policy = {'version': '0.10.0', 'issuer': ALICE,
              'epoch': '00000000-0000-4000-8000-000000000001',
              'engine': 'external-consumer-fixture/1', 'artifacts': manifest}
    expected = {'version': '0.10.0', 'profile': 'sage-execution-guard',
                'request_id': '00000000-0000-4000-8000-000000000002',
                'call_id': call, 'parent_call_id': None, 'issuer': ALICE, 'recipient': BOB,
                'tool': 'read', 'arguments': {'path': 'public.txt'},
                'original_digest': sha(b'sage-original|0.10.0\0' + (1).to_bytes(4, 'big') +
                                       (18).to_bytes(8, 'big') + b'trusted root input'),
                'policy_digest': sha(b'sage-policy|0.10.0\0' + canonical(policy)),
                'manifest_digest': sha(canonical(manifest)), 'created': 460, 'expires': 760,
                'nonce': nonce, 'keyid': ALICE + '#signing-1', 'alg': 'ed25519'}
    require(canonical(intent) == canonical(expected), 'independent original, policy and component binding')
    return call, nonce


def events(journal):
    require(journal.startswith(HEADER) and journal.endswith(b'\n'), 'Client journal framing')
    rows = [strict_json(line) for line in journal[len(HEADER):].splitlines()]
    require(1 <= len(rows) <= 42 and all(type(row) is dict and set(row) ==
            {'kind', 'id', 'at', 'intent_hex', 'result_hex'} and type(row['at']) is int for row in rows),
            'closed bounded Client events')
    return rows


def check_case(case, scenario):
    require(type(case) is dict and set(case) == {'id', 'client', 'server'}, 'closed observation')
    client, server = case['client'], case['server']
    require(type(client) is dict and set(client) == {'mode', 'status', 'effects', 'ledger_hex',
            'journal_hex', 'fence_hex', 'before_transfer_hex', 'sign_calls', 'issuance_body_hex',
            'prepare_denied', 'stage', 'owned_capture_digest'} and
            type(server) is dict and set(server) == {'mode', 'status', 'effects', 'ledger_hex', 'prepare_denied'},
            'closed external consumer records')
    allowed = scenario == 'allowed'
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
    issued_identity = check_intent(intent)
    require(fence == FENCE + sha(body).encode() + b'\n', 'exact durable fence before signer')
    if scenario == 'signing-denied':
        require(not journal and not before and decode(server['ledger_hex']) == LEDGER,
                'failed signing retains fence without journal or effect')
        return issued_identity
    before_rows = events(before)
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
    rows = events(journal)
    calls = rows[1:-1]
    require(calls and len(calls) % 2 == 0 and len(calls) <= 40, 'bounded complete handoffs')
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
            'created': 460, 'expires': 760, 'keyid': BOB + '#signing-1', 'alg': 'ed25519',
            'intent_digest': sha(raw), 'status': 'completed', 'output': {'ok': True}}),
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


def observe(client, server, scenario, binaries, directory):
    directory.mkdir()
    env = os.environ.copy(); env.update(SAGE_CONSUMER_ROOT=str(directory),
        SAGE_CONSUMER_MODE='server', SAGE_CONSUMER_SCENARIO=scenario)
    worker = subprocess.Popen([str(binaries[server])], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        end = time.monotonic() + 8
        while True:
            require(worker.poll() is None and time.monotonic() < end, 'bounded server startup')
            address = directory / 'address'
            if address.exists():
                value = address.read_text()
                if re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', value) and 1 <= int(value.rsplit(':', 1)[1]) <= 65535:
                    break
            time.sleep(.01)
        env['SAGE_CONSUMER_MODE'] = 'client'
        done = subprocess.run([str(binaries[client])], env=env, capture_output=True, timeout=20)
        require(done.returncode == 0 and done.stdout == b'EXTERNAL_MCP_CONSUMER\n',
                'external client actually executed: ' + done.stderr.decode(errors='replace')[:2000])
        output, _ = worker.communicate(timeout=8)
        require(worker.returncode == 0 and output == b'EXTERNAL_MCP_CONSUMER\n',
                'external server actually executed: ' + output.decode(errors='replace')[:2000])
        case = {'id': identity(client, server, scenario),
                'client': strict_json((directory / 'client.json').read_bytes()),
                'server': strict_json((directory / 'server.json').read_bytes())}
        check_case(case, scenario)
        return case
    finally:
        if worker.poll() is None:
            worker.kill(); worker.communicate(timeout=3)


def check_inputs():
    require(sha(LOCK.read_bytes()) == LOCK_SHA256, 'pinned external dependency lock')
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned core lock')
    require({k: sha(p.read_bytes()) for k, p in ADAPTERS.items()} == ADAPTER_SHA256,
            'external consumer source drift')


def inspect(go_root, rust_root):
    check_inputs()
    roots = {'go': check_source(go_root, GO_REVISION), 'rust': check_source(rust_root, RUST_REVISION)}
    sources = {lang: {name: sha((root / name).read_bytes()) for name in SOURCE_SHA256[lang]}
               for lang, root in roots.items()}
    require(sources == SOURCE_SHA256, 'core source drift')
    for root in roots.values():
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
                    cwd=root, text=True).strip(), 'untracked core build inputs')
    with tempfile.TemporaryDirectory(prefix='sage-mcp-consumer-') as directory:
        temp = Path(directory)
        binaries = build(temp, roots)
        cases = [observe(c, s, scenario, binaries, temp / identity(c, s, scenario))
                 for c, s, scenario in CONFIGS]
    return {'schema_version': 1, 'kind': 'external-mcp-consumer-observation', 'protocol_version': '0.10.0',
            'normative_source_revision': NORMATIVE_REVISION, 'go_revision': GO_REVISION,
            'rust_revision': RUST_REVISION, 'source_sha256': sources,
            'adapter_sha256': ADAPTER_SHA256.copy(), 'consumer_lock_sha256': LOCK_SHA256,
            'compiler_status': 'EXTERNAL_PUBLIC_CONSUMERS_BUILT',
            'status': 'ROOT_EXTERNAL_CONSUMER_BOUND', 'scope': SCOPE.copy(), 'cases': cases}


def check_report(report):
    check_inputs()
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'go_revision', 'rust_revision', 'source_sha256',
            'adapter_sha256', 'consumer_lock_sha256', 'compiler_status', 'status', 'scope', 'cases'},
            'closed report')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'external-mcp-consumer-observation' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['go_revision'] == GO_REVISION and
            report['rust_revision'] == RUST_REVISION and report['source_sha256'] == SOURCE_SHA256 and
            report['adapter_sha256'] == ADAPTER_SHA256 and report['consumer_lock_sha256'] == LOCK_SHA256 and
            report['compiler_status'] == 'EXTERNAL_PUBLIC_CONSUMERS_BUILT' and
            report['status'] == 'ROOT_EXTERNAL_CONSUMER_BOUND' and report['scope'] == SCOPE,
            'scope and provenance')
    require(type(report['cases']) is list and [case.get('id') for case in report['cases']] ==
            [identity(*config) for config in CONFIGS], 'four allowed and ten ordered denial observations')
    seen_calls, seen_nonces = set(), set()
    for case, (_, _, scenario) in zip(report['cases'], CONFIGS):
        result = check_case(case, scenario)
        if result:
            call, nonce = result
            require(call not in seen_calls and nonce not in seen_nonces, 'independent fresh issuance per observation')
            seen_calls.add(call); seen_nonces.add(nonce)
    return len(report['cases'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path); parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--report', type=Path, default=REPORT); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root) or args.output and not args.go_root:
        parser.error('supply both core roots; output requires execution')
    report = inspect(args.go_root, args.rust_root) if args.go_root else strict_json(args.report.read_bytes())
    count = check_report(report)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': count, 'status': report['status'], 'deployed_host': report['scope']['deployed_host']}))


if __name__ == '__main__':
    main()
