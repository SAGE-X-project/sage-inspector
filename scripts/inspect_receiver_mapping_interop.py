"""Observe Go/Rust native MCP exchanges whose receiver verifies by mapping.

Each server process runs the pinned core helper with
SAGE_MCP_PUBLIC_RECEIVER_MAPPING=1: it verifies intents through the core
receiver policy and a fixture mapping for one provisioned commitment and holds
no usable original request (Go replaces its fixture original; Rust's receiver
policy never supplies one). The client is the unchanged root Client. The same
independent oracle as the public MCP host observation checks every exchange.
Registry, clocks, replay and keys are local test fixtures.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from inspect_intent_issuance import build, require
from inspect_public_mcp_host import FIXTURE, check_case, command, executed, strict_json
from inspect_root_capture_parity import ROOT, NORMATIVE_REVISION, check_source, sha

GO_REVISION = 'e6c40f4bddb457702810c1058eaf863bd31293ec'
RUST_REVISION = '4f691b3526063e74c4408bef9abfa998cbaf4c0d'
REPORT = ROOT / 'docs/evidence/receiver-mapping-interop.json'
RUST_LOCK = ROOT / 'verification/0.10.0/receiver-mapping-interop/Cargo.lock'
STATUS = 'RECEIVER_MAPPING_MCP_TCP_INTEROP'
SCOPE = {'receiver_original': 'NOT_HELD', 'receiver_verification': 'PROVISIONED_COMMITMENT_MAPPING',
         'deployed_host': 'NOT_RUN', 'outer_handshake_oracle': 'NOT_RUN',
         'full_conformance': 'NOT_ESTABLISHED', 'registry': 'LOCAL_TEST_FIXTURE',
         'endpoint_replay': 'LOCAL_TEST_FIXTURE', 'effect': 'INERT_EXACT_READ'}
SOURCE_SHA256 = {
    'go': {
        'pkg/agent/guard010/mcp_admission.go': '13f59e770e8c563cb8bedb6f6ab6366926c8032dba6deef3fcbb6b2ca5ec861f',
        'pkg/agent/guard010/mcp_connection.go': '52a18eefa3218304d8d3ec2b36962ab86572b839aa9bf90db7a2a04b894f0dff',
        'pkg/agent/guard010/mcp_public.go': 'f3c495302c730349dd89f461b4a19236a36b734a8c60ffdf0c2caa6d0a47bf6d',
        'pkg/agent/guard010/mcp_public_test.go': '5405359feb3149bb02f5d4685f7764e77488b10b8f92a87d36d8ddf7ab97410d',
        'pkg/agent/guard010/receiver_policy.go': 'ff224d73028d07e78591a4fdcea6e1c93ce8758a13116400c441c62e399842c6',
        'pkg/agent/guard010/testdata/guard-rpc.json': 'f92bffa784bec1ca3541f24ba89bc11bda3de1b022081e8a0e1686b8f725ebf9',
        'pkg/agent/guard010/verify.go': '34841c42b1897a2709f2445a805162c5eef00f2da589308bf4ac651b0a047cb5',
    },
    'rust': {
        'Cargo.lock': '2b93def63db1d995ebbfae8d9903d877391c2383aa1dd0cd99e803b2d64f1c5b',
        'src/guard010/dispatch/mcp_admission.rs': '70fc0e6792833dfd585d16598aaaa1e8a1ea63c56eccaf13dbab0924c785832e',
        'src/guard010/mcp_public.rs': 'cf49f22182f5bd6787a17a281e561bb7130722ff144fae33eb700442f33a14ff',
        'src/guard010/mod.rs': '3f2952b9c51768dd0f3a985ef1e9c7aecc5ab8a21abecb8c8dab5df8a851132c',
        'src/guard010/testdata/guard-rpc.json': 'f92bffa784bec1ca3541f24ba89bc11bda3de1b022081e8a0e1686b8f725ebf9',
        'src/hpke/completion010/mcp_admission_tests.rs': 'e2fe9f46c08795b73ca7b8e665cf54b422a3c5d8e30967b71165c59e28277e6a',
        'src/hpke/completion010/mcp_public_tests.rs': '634319a5b1f813d5f2a696b701c6b447d1979a0bfc1b73f7f577a31f08c014c6',
        'src/hpke/completion010/mcp_reply_tests.rs': '42cad7c21626843dd6148672e4857dd57d36a3c8abde1bfc0a296eb32128af35',
        'src/hpke/completion010/mcp_transport_tests.rs': '323f6402babbe9b8fe6fb876405b222a851740da6b66638816a0583973f28aff',
        'src/hpke/completion010/tests.rs': '5d95ec799c7b44c53eed9f67c093a6e2f8ffb0d5c5e446e57b04ec208f0ec468',
    },
}
DIRECTIONS = [('go', 'go'), ('rust', 'rust'), ('go', 'rust'), ('rust', 'go')]


def observe(client, server, binaries, roots, directory):
    directory.mkdir()
    env = os.environ.copy()
    env.update(SAGE_MCP_PUBLIC_TEST_ROOT=str(directory), SAGE_MCP_PUBLIC_TEST_MODE='server',
               SAGE_MCP_PUBLIC_RECEIVER_MAPPING='1')
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
        client_env = dict(env, SAGE_MCP_PUBLIC_TEST_MODE='client')
        client_env.pop('SAGE_MCP_PUBLIC_RECEIVER_MAPPING')
        done = subprocess.run(command(client, binaries), cwd=cwd(client), env=client_env,
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
            worker.kill()
            worker.communicate(timeout=3)


def inspect(go_root, rust_root):
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned Rust dependency lock')
    roots = {'go': check_source(go_root, GO_REVISION), 'rust': check_source(rust_root, RUST_REVISION)}
    sources = {lang: {name: sha((root / name).read_bytes()) for name in SOURCE_SHA256[lang]}
               for lang, root in roots.items()}
    require(sources == SOURCE_SHA256, 'receiver mapping source drift')
    for root in roots.values():
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'],
                cwd=root, text=True).strip(), 'untracked core inputs')
    with tempfile.TemporaryDirectory(prefix='sage-receiver-mapping-') as directory:
        temp = Path(directory)
        binaries = build(temp, roots['go'], roots['rust'])
        cases = [observe(c, s, binaries, roots, temp / (c + '-to-' + s)) for c, s in DIRECTIONS]
    report = {'schema_version': 1, 'kind': 'receiver-mapping-mcp-observation', 'protocol_version': '0.10.0',
              'normative_source_revision': NORMATIVE_REVISION, 'go_revision': GO_REVISION,
              'rust_revision': RUST_REVISION, 'source_sha256': sources, 'fixture_sha256': sha(FIXTURE.read_bytes()),
              'status': STATUS, 'scope': SCOPE.copy(), 'cases': cases}
    check_report(report)
    return report


def check_report(report):
    require(type(report) is dict and set(report) == {'schema_version', 'kind', 'protocol_version',
            'normative_source_revision', 'go_revision', 'rust_revision', 'source_sha256', 'fixture_sha256',
            'status', 'scope', 'cases'}, 'closed report')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['kind'] == 'receiver-mapping-mcp-observation' and report['protocol_version'] == '0.10.0' and
            report['normative_source_revision'] == NORMATIVE_REVISION and report['go_revision'] == GO_REVISION and
            report['rust_revision'] == RUST_REVISION and report['source_sha256'] == SOURCE_SHA256 and
            report['fixture_sha256'] == sha(FIXTURE.read_bytes()) and report['status'] == STATUS and
            report['scope'] == SCOPE, 'scope and provenance')
    require(sha(RUST_LOCK.read_bytes()) == SOURCE_SHA256['rust']['Cargo.lock'], 'pinned Rust dependency lock')
    require(type(report['cases']) is list and [c.get('id') for c in report['cases'] if type(c) is dict] ==
            [c + '-to-' + s for c, s in DIRECTIONS] and len(report['cases']) == len(DIRECTIONS),
            'four distinct ordered directions')
    for case in report['cases']:
        check_case(case)
    return len(report['cases'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path)
    parser.add_argument('--rust-root', type=Path)
    parser.add_argument('--report', type=Path, default=REPORT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.go_root) != bool(args.rust_root) or args.output and not args.go_root:
        parser.error('supply both core roots; output requires execution')
    report = inspect(args.go_root, args.rust_root) if args.go_root else strict_json(args.report.read_bytes())
    count = check_report(report)
    if args.output:
        with open(args.output, 'x') as out:
            out.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': count, 'status': report['status'],
                      'receiver_original': report['scope']['receiver_original']}))


if __name__ == '__main__':
    main()
