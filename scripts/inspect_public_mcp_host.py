"""Check public native MCP APIs and bounded localhost root exchanges.

The signature/journal oracle is independent of both cores. Native endpoint and
registry fixtures are not deployed providers or complete conformance evidence.
"""
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from inspect_intent_issuance import RUST_LOCK, build, canonical, require
from inspect_root_capture_parity import NORMATIVE_REVISION, ROOT, UUID, check_source, sha

GO_REVISION = '6a99b558a18d9c33ae9a07ce2ffa75af495661d0'
RUST_REVISION = 'cc83fba11d0e155d31af67dbdd840c9ab8cb0d9e'
REPORT = ROOT / 'docs/evidence/public-mcp-host.json'
FIXTURE = ROOT / 'vectors/0.10.0/guard-rpc.json'
PROBE_LOCK = ROOT / 'verification/0.10.0/public-mcp-host/Cargo.lock'
PROBE_LOCK_SHA256 = 'cb93b5cc1cd10df87cb93e20bd840eee0820ea8342553684da96619fc2eff32b'
HEADER = b'sage-guard-client|0.10.0\n'
LEDGER = b'sage-execution-ledger|0.10.0\n'
ALICE = 'did:sage:web:agent.example:alice'
BOB = 'did:sage:web:agent.example:bob'
SCOPE = {'deployed_host': 'NOT_RUN', 'independent_hop_execution': 'NOT_RUN',
         'issuer_consumer_binding': 'NOT_RUN', 'outer_handshake_oracle': 'NOT_RUN',
         'full_conformance': 'NOT_ESTABLISHED', 'registry': 'LOCAL_TEST_FIXTURE',
         'endpoint_replay': 'LOCAL_TEST_FIXTURE', 'effect': 'INERT_EXACT_READ'}
SOURCE_FILES = {
    'go': ['pkg/agent/guard010/mcp_public.go', 'pkg/agent/guard010/mcp_public_test.go',
           'pkg/agent/guard010/mcp_connection.go', 'pkg/agent/guard010/testdata/guard-rpc.json'],
    'rust': ['src/guard010/mcp_public.rs', 'src/guard010/mod.rs',
             'src/hpke/completion010/mcp_public_tests.rs',
             'src/hpke/completion010/mcp_transport_tests.rs',
             'src/hpke/completion010/mcp_admission_tests.rs',
             'src/hpke/completion010/mcp_reply_tests.rs',
             'src/hpke/completion010/tests.rs', 'src/guard010/testdata/guard-rpc.json',
             'Cargo.lock'],
}
SOURCE_SHA256 = {
    "go": {
        "pkg/agent/guard010/mcp_connection.go": "52a18eefa3218304d8d3ec2b36962ab86572b839aa9bf90db7a2a04b894f0dff",
        "pkg/agent/guard010/mcp_public.go": "f3c495302c730349dd89f461b4a19236a36b734a8c60ffdf0c2caa6d0a47bf6d",
        "pkg/agent/guard010/mcp_public_test.go": "648efd266359b85fc557be8a460e9c5395538e744088ad6320e5989724846252",
        "pkg/agent/guard010/testdata/guard-rpc.json": "f92bffa784bec1ca3541f24ba89bc11bda3de1b022081e8a0e1686b8f725ebf9"
    },
    "rust": {
        "Cargo.lock": "04099b5ee7c1320fb249112b1fba052aad1a433cc26d60e4537db108b69d6a38",
        "src/guard010/mcp_public.rs": "cf49f22182f5bd6787a17a281e561bb7130722ff144fae33eb700442f33a14ff",
        "src/guard010/mod.rs": "a43263e9acada1a96e90723e0e94df7bb01ef812c2ac1355c74306ad136fc268",
        "src/guard010/testdata/guard-rpc.json": "f92bffa784bec1ca3541f24ba89bc11bda3de1b022081e8a0e1686b8f725ebf9",
        "src/hpke/completion010/mcp_admission_tests.rs": "e2fe9f46c08795b73ca7b8e665cf54b422a3c5d8e30967b71165c59e28277e6a",
        "src/hpke/completion010/mcp_public_tests.rs": "ba7471de9c455b46a0412250546baf34baff3c8ab24a5f1ddb02eb83659519e8",
        "src/hpke/completion010/mcp_reply_tests.rs": "42cad7c21626843dd6148672e4857dd57d36a3c8abde1bfc0a296eb32128af35",
        "src/hpke/completion010/mcp_transport_tests.rs": "323f6402babbe9b8fe6fb876405b222a851740da6b66638816a0583973f28aff",
        "src/hpke/completion010/tests.rs": "e644cf8af81dac019c68a41c53c66e303a15b01be242d0888b7e60efb7792a26"
    }
}
DIRECTIONS = [('go', 'go'), ('rust', 'rust'), ('go', 'rust'), ('rust', 'go')]


def strict_json(raw):
    def object_hook(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate artifact member')
            value[key] = item
        return value
    def invalid(value):
        raise ValueError('nonfinite artifact number: ' + value)
    return json.loads(raw, object_pairs_hook=object_hook, parse_constant=invalid)


def decode(value):
    require(type(value) is str and len(value) <= 200000 and len(value) % 2 == 0 and
            re.fullmatch('[0-9a-f]*', value) is not None, 'bounded artifact hex')
    return bytes.fromhex(value)


def signed(raw, field, seed):
    env = strict_json(raw)
    require(type(env) is dict and set(env) == {field, 'proof'} and
            raw == canonical(env) and type(env[field]) is dict, 'canonical signed envelope')
    proof = env['proof']
    require(type(proof) is str and re.fullmatch('[A-Za-z0-9_-]{86}', proof) is not None,
            'Ed25519 proof shape')
    signature = base64.urlsafe_b64decode(proof + '==')
    require(base64.urlsafe_b64encode(signature).rstrip(b'=').decode() == proof,
            'canonical proof')
    domain = b'sage-execution-intent|0.10.0\0' if field == 'intent' else b'sage-tool-result|0.10.0\0'
    Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().verify(
        signature, domain + canonical(env[field]))
    return env[field]


def expected_intent():
    f = copy.deepcopy(strict_json(FIXTURE.read_bytes())['input'])
    expected = strict_json(bytes.fromhex(f['envelope_hex']))['intent']
    f['approved_policy']['issuer'] = ALICE
    expected.update(issuer=ALICE, recipient=BOB, keyid=ALICE + '#signing-1',
                    created=460, expires=760,
                    original_digest=sha(b'sage-original|0.10.0\0' +
                                        (1).to_bytes(4, 'big') + (18).to_bytes(8, 'big') + b'trusted root input'),
                    policy_digest=sha(b'sage-policy|0.10.0\0' + canonical(f['approved_policy'])),
                    manifest_digest=sha(canonical(f['approved_manifest'])))
    return expected


def check_case(case):
    require(type(case) is dict and set(case) == {'id', 'client', 'server'}, 'closed observation')
    client, server = case['client'], case['server']
    require(type(client) is dict and set(client) == {'mode', 'status', 'effects', 'ledger_hex', 'journal_hex'} and
            type(server) is dict and set(server) == {'mode', 'status', 'effects', 'ledger_hex'}, 'closed native record')
    require(client['mode'] == 'client' and server['mode'] == 'server' and
            client['status'] == server['status'] == 'completed' and
            type(client['effects']) is int and client['effects'] == 0 and
            type(server['effects']) is int and server['effects'] == 1 and
            decode(client['ledger_hex']) == LEDGER, 'one measured inert effect')
    journal = decode(client['journal_hex'])
    require(journal.startswith(HEADER) and journal.endswith(b'\n'), 'Client journal framing')
    rows = [strict_json(line) for line in journal[len(HEADER):].splitlines()]
    require(4 <= len(rows) <= 42 and all(type(row) is dict and set(row) ==
            {'kind', 'id', 'at', 'intent_hex', 'result_hex'} and type(row['at']) is int for row in rows), 'closed bounded Client events')
    first, terminal = rows[0], rows[-1]
    raw = decode(first['intent_hex'])
    require(first == {'kind': 'open', 'id': '', 'at': 0, 'intent_hex': raw.hex(), 'result_hex': ''},
            'one journaled root')
    intent = signed(raw, 'intent', 1)
    require(canonical(intent) == canonical(expected_intent()), 'independent captured root binding')
    calls = rows[1:-1]
    require(len(calls) % 2 == 0 and calls, 'complete bounded handoffs')
    seen = set()
    for index in range(0, len(calls), 2):
        sent, closed = calls[index:index + 2]
        ident = sent['id']
        require(type(ident) is str and UUID.fullmatch(ident) is not None and ident not in seen,
                'fresh outer attempt identity')
        seen.add(ident)
        require(sent == {'kind': 'send', 'id': ident, 'at': 460000 + 1000 * (index // 2),
                         'intent_hex': '', 'result_hex': ''} and
                type(sent['at']) is int and closed == {'kind': 'close', 'id': ident, 'at': 0,
                                                       'intent_hex': '', 'result_hex': ''},
                'identity-preserving retry cadence and consumption')
    result_raw = decode(terminal['result_hex'])
    require(terminal == {'kind': 'terminal', 'id': calls[-1]['id'], 'at': 0,
                         'intent_hex': '', 'result_hex': result_raw.hex()}, 'one final terminal consumption')
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
    require(canonical(entries) == canonical([dict(expected, state=state, result_hex=result_raw.hex() if state == 'COMPLETED' else '')
                        for state in ('RESERVED', 'EXECUTING', 'COMPLETED')]), 'one durable execution and exact result')


def probe_source(language, private=False):
    if language == 'go':
        if private:
            body = 'var c guard010.MCPConnection; _ = c.state'
        else:
            body = '''var _ *guard010.MCPHost; var _ *guard010.MCPConnection
var _ *guard010.MCPHostServices; var _ *guard010.MCPHostBounds
var _ *guard010.MCPConnectionConfig; var _ *guard010.MCPClientServices
var _ *guard010.MCPHopServices; var _ guard010.MCPExecutor; var _ guard010.MCPConnectionHandler
_ = guard010.OpenMCPHost; _ = guard010.MCPInitiator; _ = guard010.MCPResponder
_ = (*guard010.MCPHost).Close; _ = (*guard010.MCPHost).Connect; _ = (*guard010.MCPHost).Serve
_ = (*guard010.MCPConnection).ServeOne; _ = (*guard010.MCPConnection).OpenRootClient
_ = (*guard010.MCPConnection).OpenHopClient; _ = (*guard010.MCPConnection).Exchange'''
        return 'package main\nimport "github.com/sage-x-project/sage/pkg/agent/guard010"\nfunc main() {\n' + body + '\n}\n'
    if private:
        return 'use sage_crypto_core::guard010::MCPConnection;\nfn hidden(c: MCPConnection) { let _ = c.inner; }\nfn main() {}\n'
    return '''use sage_crypto_core::guard010::*;
fn main() {
let _ = std::mem::size_of::<MCPHostServices>(); let _ = std::mem::size_of::<MCPHostBounds>();
let _ = std::mem::size_of::<MCPConnectionConfig>(); let _ = std::mem::size_of::<MCPClientServices>();
let _ = std::mem::size_of::<MCPHopServices>(); let _ = std::mem::size_of::<MCPListener>();
let _ = std::mem::size_of::<MCPCancellation>(); let _ = std::mem::size_of::<Box<dyn MCPExecutor>>();
let _ = std::mem::size_of::<Box<dyn MCPConnectionHandler>>(); let _ = MCPRole::Responder;
let _ = MCPHost::open; let _ = MCPHost::close; let _ = MCPHost::connect; let _ = MCPHost::serve;
let _ = MCPConnection::serve_one; let _ = MCPConnection::open_root_client;
let _ = MCPConnection::open_hop_client; let _ = MCPConnection::exchange;
}
'''


def compile_probes(temp, roots):
    require(sha(PROBE_LOCK.read_bytes()) == PROBE_LOCK_SHA256, 'pinned external consumer lock')
    env = os.environ.copy()
    env.update(GOPROXY='off', GOFLAGS='-mod=mod', CARGO_NET_OFFLINE='true',
               GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    for lang in ('go', 'rust'):
        directory = temp / (lang + '-external'); directory.mkdir()
        if lang == 'go':
            source = directory / 'main.go'
            (directory / 'go.mod').write_text('module sage-inspector-public-mcp\n\ngo 1.26.0\n'
                'require github.com/sage-x-project/sage v0.0.0\n' +
                f'replace github.com/sage-x-project/sage => {roots[lang]}\n')
            command = ['go', 'build', '-o', str(temp / 'go-public-probe'), '.']
        else:
            (directory / 'src').mkdir(); source = directory / 'src/main.rs'
            (directory / 'Cargo.toml').write_text('[package]\nname="public_mcp_probe"\nversion="0.0.0"\n'
                'edition="2021"\nrust-version="1.88"\n[dependencies]\n' +
                f'sage_crypto_core={{path={json.dumps(str(roots[lang]))}}}\n')
            (directory / 'Cargo.lock').write_bytes(PROBE_LOCK.read_bytes())
            command = ['cargo', 'build', '--locked', '--offline', '--quiet']
        source.write_text(probe_source(lang))
        subprocess.run(command, cwd=directory, env=env, check=True, timeout=300)
        source.write_text(probe_source(lang, True))
        done = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=300)
        require(done.returncode != 0 and ('c.state' in done.stderr and 'unexported' in done.stderr if lang == 'go'
                else 'E0616' in done.stderr and 'inner' in done.stderr and 'private' in done.stderr),
                'specific private connection compiler rejection')


def command(lang, binaries):
    args = ['-test.run=^TestMCPPublicProcessHelper$'] if lang == 'go' else [
        '--exact', 'hpke::completion010::tests::mcp_admission_tests::mcp_reply_tests::mcp_transport_tests::mcp_public_tests::public_process_helper']
    return [str(binaries[lang]), *args]


def executed(lang, done):
    require(done.returncode == 0 and (b'PASS' in done.stdout if lang == 'go' else
            b'1 passed; 0 failed' in done.stdout), 'native helper actually executed')


def observe(client, server, binaries, roots, directory):
    directory.mkdir()
    env = os.environ.copy(); env.update(SAGE_MCP_PUBLIC_TEST_ROOT=str(directory), SAGE_MCP_PUBLIC_TEST_MODE='server')
    cwd = lambda lang: roots[lang] / 'pkg/agent/guard010' if lang == 'go' else roots[lang]
    worker = subprocess.Popen(command(server, binaries), cwd=cwd(server), env=env,
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
        env['SAGE_MCP_PUBLIC_TEST_MODE'] = 'client'
        done = subprocess.run(command(client, binaries), cwd=cwd(client), env=env,
                              capture_output=True, timeout=20)
        executed(client, done)
        output, _ = worker.communicate(timeout=8)
        executed(server, subprocess.CompletedProcess([], worker.returncode, output))
        case = {'id': client + '-to-' + server,
                'client': strict_json((directory / 'client.json').read_bytes()),
                'server': strict_json((directory / 'server.json').read_bytes())}
        check_case(case)
        return case
    finally:
        if worker.poll() is None:
            worker.kill(); worker.communicate(timeout=3)


def inspect(go_root, rust_root):
    require(sha(PROBE_LOCK.read_bytes()) == PROBE_LOCK_SHA256, 'pinned external consumer lock')
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned Rust dependency lock')
    roots = {'go': check_source(go_root, GO_REVISION), 'rust': check_source(rust_root, RUST_REVISION)}
    sources = {lang: {name: sha((root / name).read_bytes()) for name in SOURCE_FILES[lang]} for lang, root in roots.items()}
    require(sources == SOURCE_SHA256, 'public MCP source drift')
    for root in roots.values():
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, text=True).strip(), 'untracked core inputs')
    with tempfile.TemporaryDirectory(prefix='sage-public-mcp-') as directory:
        temp = Path(directory)
        binaries = build(temp, roots['go'], roots['rust'])
        compile_probes(temp, roots)
        cases = [observe(client, server, binaries, roots, temp / (client + '-to-' + server)) for client, server in DIRECTIONS]
    return {'schema_version': 1, 'kind': 'public-native-mcp-host-observation', 'protocol_version': '0.10.0',
            'normative_source_revision': NORMATIVE_REVISION, 'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
            'source_sha256': sources, 'fixture_sha256': sha(FIXTURE.read_bytes()),
            'probe_sha256': {lang: {'public': sha(probe_source(lang).encode()), 'private': sha(probe_source(lang, True).encode())} for lang in ('go', 'rust')},
            'probe_lock_sha256': PROBE_LOCK_SHA256, 'compiler_status': 'PUBLIC_API_AND_PRIVATE_STATE_CHECKED', 'status': 'ROOT_MCP_TCP_INTEROP', 'scope': SCOPE.copy(), 'cases': cases}


def check_report(report):
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version', 'normative_source_revision',
            'go_revision', 'rust_revision', 'source_sha256', 'fixture_sha256', 'probe_sha256', 'probe_lock_sha256', 'compiler_status', 'status', 'scope', 'cases'}, 'closed report')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'public-native-mcp-host-observation' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['go_revision'] == GO_REVISION and
            report['rust_revision'] == RUST_REVISION and report['source_sha256'] == SOURCE_SHA256 and
            report['fixture_sha256'] == sha(FIXTURE.read_bytes()) and report['probe_lock_sha256'] == PROBE_LOCK_SHA256 and
            sha(PROBE_LOCK.read_bytes()) == PROBE_LOCK_SHA256 and report['scope'] == SCOPE and
            report['compiler_status'] == 'PUBLIC_API_AND_PRIVATE_STATE_CHECKED' and report['status'] == 'ROOT_MCP_TCP_INTEROP', 'scope and provenance')
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned Rust dependency lock')
    require(report['probe_sha256'] == {lang: {'public': sha(probe_source(lang).encode()), 'private': sha(probe_source(lang, True).encode())} for lang in ('go', 'rust')}, 'external probe bytes')
    require(type(report['cases']) is list and [case['id'] for case in report['cases']] ==
            [client + '-to-' + server for client, server in DIRECTIONS], 'four distinct ordered directions')
    for case in report['cases']:
        check_case(case)
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
