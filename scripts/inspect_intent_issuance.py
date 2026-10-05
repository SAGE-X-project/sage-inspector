"""Observe bounded root issuance through native test processes and an independent oracle.

This checks root approval/issuance and durable cross-core recovery. It does not
inspect a deployed host, independently execute hops, or close complete cases.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from inspect_root_capture_parity import NORMATIVE_REVISION, ROOT, UUID, check_source, sha

GO_REVISION = 'd9d61d5d8daa9b2894ba6eddea2a771ccfe7ab54'
RUST_REVISION = 'eb0529922f2dd632357ceb1ed89eefb17cda9a29'
EVIDENCE = ROOT / 'docs/evidence/intent-issuance.json'
FIXTURE = ROOT / 'vectors/0.10.0/guard-client.json'
HEADER = b'sage-guard-client|0.10.0\n'
FENCE = b'sage-intent-issuance|0.10.0\n'
SOURCE_FILES = {
    'go': ['pkg/agent/guard010/issuance.go', 'pkg/agent/guard010/issuance_test.go',
           'pkg/agent/guard010/testdata/guard-client.json'],
    'rust': ['src/guard010/issuance.rs', 'src/guard010/issuance_tests.rs',
             'src/guard010/testdata/guard-client.json'],
}

SOURCE_SHA256 = {
    "go": {
        "pkg/agent/guard010/issuance.go": "e0537b5418eca3e10bb98db5858636e659811ba759ec8d698199ee6f5b555032",
        "pkg/agent/guard010/issuance_test.go": "706a160e4a7de0ab799e9c6c0312933df7bace3b97548fec4658fab4a9e9a1c9",
        "pkg/agent/guard010/testdata/guard-client.json": "2c7b043f6f761a2eff0e7eea89cf838746a31a221c31e2d82b47d30b6937c271"
    },
    "rust": {
        "src/guard010/issuance.rs": "7bd94da4b694ff9a3793e432323362df8a02992f8734e0e514ff6b62692d1cb4",
        "src/guard010/issuance_tests.rs": "7faeb0ba20bf44b07b94cc4405881947635adcccc667ceb6eb8f7baf76a178f2",
        "src/guard010/testdata/guard-client.json": "2c7b043f6f761a2eff0e7eea89cf838746a31a221c31e2d82b47d30b6937c271"
    }
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def decode(value):
    require(type(value) is str and len(value) <= 20000 and len(value) % 2 == 0 and
            re.fullmatch('[0-9a-f]*', value) is not None, 'bounded artifact hex')
    return bytes.fromhex(value)


def fixture():
    raw = FIXTURE.read_bytes()
    value = json.loads(raw)['input']
    public = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        b'public Guard fixture issuer').digest()).public_key()
    original = b'trusted root input'
    digest = sha(b'sage-original|0.10.0\0' + struct.pack('>I', 1) +
                 struct.pack('>Q', len(original)) + original)
    return value, public, digest


def check_journals(before, after, marker):
    require(before.startswith(HEADER) and after.startswith(before) and
            before.endswith(b'\n') and after.endswith(b'\n'), 'journal append-only recovery')
    rows = [json.loads(line) for line in after[len(HEADER):].splitlines()]
    require(len(rows) == 3 and before == HEADER +
            b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in rows[:2]),
            'exact pre-restart journal')
    open_row = rows[0]
    require(set(open_row) == {'kind', 'id', 'at', 'intent_hex', 'result_hex'} and
            open_row['kind'] == 'open' and open_row['id'] == '' and
            type(open_row['at']) is int and open_row['at'] == 0 and open_row['result_hex'] == '',
            'one journaled intent')
    for row, number, at in zip(rows[1:], (40, 41), (1700000000000, 1700000001000)):
        require(row == {'kind': 'send', 'id': f'00000000-0000-4000-8000-{number:012d}',
                        'at': at, 'intent_hex': '', 'result_hex': ''}, 'two fixed bounded handoffs')
    raw = decode(open_row['intent_hex'])
    envelope = json.loads(raw)
    require(set(envelope) == {'intent', 'proof'} and raw == canonical(envelope), 'canonical envelope')
    intent = envelope['intent']
    require(set(intent) == set('version profile request_id call_id parent_call_id original_digest issuer recipient tool arguments policy_digest manifest_digest created expires nonce keyid alg'.split()), 'closed intent')
    approved, public, original = fixture()
    require(intent['version'] == '0.10.0' and intent['profile'] == 'sage-execution-guard' and
            intent['request_id'] == '00000000-0000-4000-8000-000000000002' and
            UUID.fullmatch(intent['call_id']) is not None and intent['parent_call_id'] is None and
            intent['original_digest'] == original and intent['issuer'] == approved['expected_issuer'] and
            intent['recipient'] == approved['expected_recipient'] and intent['tool'] == 'read' and
            intent['arguments'] == {'path': 'notes.txt'} and intent['alg'] == 'ed25519' and
            intent['keyid'] == approved['expected_issuer'] + '#signing-1' and
            type(intent['created']) is int and intent['created'] == 1700000000 and
            type(intent['expires']) is int and intent['expires'] == 1700000300 and
            intent['policy_digest'] == sha(b'sage-policy|0.10.0\0' + canonical(approved['approved_policy'])) and
            intent['manifest_digest'] == sha(canonical(approved['approved_manifest'])), 'protected issuance binding')
    nonce = intent['nonce']
    require(type(nonce) is str and len(nonce) == 22 and
            base64.urlsafe_b64encode(base64.urlsafe_b64decode(nonce + '==')).rstrip(b'=').decode() == nonce and
            len(base64.urlsafe_b64decode(nonce + '==')) == 16, 'canonical random nonce')
    require(type(envelope['proof']) is str and len(envelope['proof']) == 86, 'Ed25519 proof shape')
    proof = base64.urlsafe_b64decode(envelope['proof'] + '==')
    require(len(proof) == 64 and base64.urlsafe_b64encode(proof).rstrip(b'=').decode() == envelope['proof'], 'raw proof')
    public.verify(proof, b'sage-execution-intent|0.10.0\0' + canonical(intent))
    require(marker == FENCE + sha(canonical(intent)).encode() + b'\n', 'durable issuance identity')
    return intent['call_id'], nonce


def build(temp, go_root, rust_root):
    environment = os.environ.copy()
    environment.update(GOPROXY='off', GOFLAGS='-mod=readonly', CARGO_NET_OFFLINE='true',
                       GOCACHE=str(temp / 'go-cache'), CARGO_TARGET_DIR=str(temp / 'rust-target'))
    go_binary = temp / 'go-tests'
    subprocess.run(['go', 'test', '-c', '-o', str(go_binary), './pkg/agent/guard010'],
                   cwd=go_root, env=environment, check=True, timeout=300)
    result = subprocess.run(['cargo', 'test', '--offline', '--locked', '--lib', '--no-run', '--message-format=json'],
                            cwd=rust_root, env=environment, capture_output=True, text=True,
                            check=True, timeout=300)
    binaries = [row['executable'] for row in map(json.loads, result.stdout.splitlines())
                if row.get('reason') == 'compiler-artifact' and row.get('executable') and
                row.get('profile', {}).get('test') and row['target']['name'] == 'sage_crypto_core']
    require(len(binaries) == 1, 'one native Rust test binary')
    return {'go': go_binary, 'rust': Path(binaries[0])}


def run(language, binaries, roots, path, mode):
    args = (['-test.run=^TestIntentIssuerProcessHelper$'] if language == 'go' else
            ['--exact', 'guard010::issuance_tests::issuer_process_helper'])
    environment = os.environ.copy()
    environment.update(SAGE_INTENT_ISSUANCE_TEST_PATH=str(path), SAGE_INTENT_ISSUANCE_TEST_MODE=mode)
    cwd = roots[language] / 'pkg/agent/guard010' if language == 'go' else roots[language]
    result = subprocess.run([str(binaries[language]), *args], cwd=cwd, env=environment,
                            capture_output=True, timeout=20)
    require(result.returncode == 0, 'bounded native issuance process failure')
    require((b'PASS' in result.stdout if language == 'go' else
             b'1 passed; 0 failed' in result.stdout), 'helper test actually executed')


def inspect(go_root, rust_root):
    roots = {'go': check_source(go_root, GO_REVISION), 'rust': check_source(rust_root, RUST_REVISION)}
    sources = {language: {name: sha((root / name).read_bytes()) for name in SOURCE_FILES[language]}
               for language, root in roots.items()}
    require(sources == SOURCE_SHA256, 'issuance source drift before execution')
    for root in roots.values():
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
                                            cwd=root, text=True).strip(), 'untracked core inputs')
    cases = []
    with tempfile.TemporaryDirectory(prefix='sage-issuance-') as directory:
        temp = Path(directory)
        binaries = build(temp, roots['go'], roots['rust'])
        for writer, reader in (('go', 'rust'), ('rust', 'go')):
            path = temp / (writer + '-journal')
            run(writer, binaries, roots, path, 'issue')
            before = path.read_bytes()
            marker = path.with_name(path.name + '.issuance').read_bytes()
            run(reader, binaries, roots, path, 'reopen')
            cases.append({'id': f'{writer}-to-{reader}-resume', 'before_hex': before.hex(),
                          'after_hex': path.read_bytes().hex(), 'fence_hex': marker.hex()})
            failed = temp / (writer + '-failed')
            run(writer, binaries, roots, failed, 'sign-failure')
            require(not failed.exists(), 'failed writer created journal')
            marker = failed.with_name(failed.name + '.issuance').read_bytes()
            run(reader, binaries, roots, failed, 'fenced')
            require(not failed.exists(), 'fenced reader created journal')
            cases.append({'id': f'{writer}-to-{reader}-fenced-reissue', 'journal': 'ABSENT',
                          'before_fence_hex': marker.hex(),
                          'after_fence_hex': failed.with_name(failed.name + '.issuance').read_bytes().hex()})
    return {'schema_version': 1, 'kind': 'native-intent-issuance-interop',
            'protocol_version': '0.10.0', 'normative_source_revision': NORMATIVE_REVISION,
            'go_revision': GO_REVISION, 'rust_revision': RUST_REVISION,
            'source_sha256': sources, 'fixture_sha256': sha(FIXTURE.read_bytes()),
            'status': 'ROOT_ISSUANCE_INTEROP', 'deployed_host': 'NOT_RUN',
            'independent_hop_execution': 'NOT_RUN', 'full_conformance': 'NOT_ESTABLISHED',
            'cases': cases}


def check_report(report):
    require(set(report) == {'schema_version', 'kind', 'protocol_version', 'normative_source_revision',
            'go_revision', 'rust_revision', 'source_sha256', 'fixture_sha256', 'status',
            'deployed_host', 'independent_hop_execution', 'full_conformance', 'cases'} and
            type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'native-intent-issuance-interop' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['go_revision'] == GO_REVISION and
            report['rust_revision'] == RUST_REVISION and report['fixture_sha256'] == sha(FIXTURE.read_bytes()) and
            report['status'] == 'ROOT_ISSUANCE_INTEROP' and report['deployed_host'] == 'NOT_RUN' and
            report['independent_hop_execution'] == 'NOT_RUN' and report['full_conformance'] == 'NOT_ESTABLISHED',
            'issuance report scope and provenance')
    require(report['source_sha256'] == SOURCE_SHA256, 'pinned issuance source bytes')
    rows = report['cases']
    require(type(rows) is list and len(rows) == 4 and [row['id'] for row in rows] ==
            ['go-to-rust-resume', 'go-to-rust-fenced-reissue', 'rust-to-go-resume', 'rust-to-go-fenced-reissue'],
            'four bounded observations')
    identities = []
    for row in rows:
        if row['id'].endswith('-resume'):
            require(set(row) == {'id', 'before_hex', 'after_hex', 'fence_hex'}, 'closed resume observation')
            identities.append(check_journals(decode(row['before_hex']), decode(row['after_hex']), decode(row['fence_hex'])))
        else:
            require(set(row) == {'id', 'journal', 'before_fence_hex', 'after_fence_hex'} and row['journal'] == 'ABSENT' and
                    row['before_fence_hex'] == row['after_fence_hex'] and
                    re.fullmatch(re.escape(FENCE) + b'[0-9a-f]{64}\n', decode(row['before_fence_hex'])) is not None,
                    'failed issuance preserves its fence without a Client journal')
    require(len(set(value[0] for value in identities)) == 2 and len(set(value[1] for value in identities)) == 2,
            'fresh independent call identities and nonces')
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path, default=EVIDENCE)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root) or args.output and not args.go_root:
        parser.error('supply both roots; output requires execution')
    report = inspect(args.go_root, args.rust_root) if args.go_root else json.loads(args.report.read_text())
    count = check_report(report)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': count, 'status': report['status'], 'deployed_host': report['deployed_host']}))


if __name__ == '__main__':
    main()
