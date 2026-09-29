"""Independently audit signed Client and MCP pending-state fixtures."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_exec_pending_vectors import IDS, SPEC, cases


SOURCE = 'vectors/0.10.0/exec-pending.json'


def verify_result(envelope_hex, public_hex, intent_sha, status):
    envelope = load(bytes.fromhex(envelope_hex))
    result = envelope['result']
    signature = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
        signature, b'sage-tool-result|0.10.0\x00' +
        json.dumps(result, sort_keys=True, separators=(',', ':')).encode())
    require(result['status'] == status and
            result['intent_digest'] == intent_sha and
            result['output'] == {}, 'signed status and exact intent')


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    client = load((root / 'vectors/0.10.0/guard-client.json').read_bytes())
    mcp = load((root / 'vectors/0.10.0/guard-mcp.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['client_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-client.json').read_bytes()) ==
            '2c7b043f6f761a2eff0e7eea89cf838746a31a221c31e2d82b47d30b6937c271' and
            suite['mcp_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-mcp.json').read_bytes()) ==
            'df2e965ade565d989077475df9d1648013b1169e3b8c21ae9db0ce36c63c6754' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned pending source and case identities')
    for case, (ident, inp, expected) in zip(suite['cases'], cases()):
        require(case == {'id': ident, 'input': inp, 'expected': expected},
                'pending case fixture contract: ' + ident)
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': inp, 'expected': expected} and
                any(row == {'id': ident, 'track': 'runtime',
                            'fixture': path,
                            'fixture_sha256': sha((root / path).read_bytes()),
                            'coverage': 'partial'}
                    for row in bindings['bindings']),
                'pending partial binding: ' + ident)
    first = suite['cases'][0]
    source = first['input']['input']
    scenarios = source['scenarios']
    require([row['name'] for row in scenarios] ==
            ['poll-boundary', 'unknown'] and
            all('expected' not in step for row in scenarios
                for step in row['steps']) and
            source['configuration'] == client['input'] and
            source['results'] == client['results'],
            'client input excludes answer and retains signed envelopes')
    intent_sha = hashlib.sha256(bytes.fromhex(
        client['input']['envelope_hex'])).hexdigest()
    verify_result(client['results']['pending'],
                  client['public_key_hex'], intent_sha, 'pending')
    verify_result(client['results']['unknown'],
                  client['public_key_hex'], intent_sha, 'unknown')
    state = first['expected']['output']['scenarios']
    ordinary = state['poll-boundary']['steps']
    unknown = state['unknown']['steps']
    require(ordinary[6]['status'] == 'pending' and
            ordinary[6]['first'] is False and
            ordinary[7]['status'] == 'completed' and
            unknown[2]['status'] == 'unknown' and
            unknown[2]['first'] is True and
            unknown[4]['ok'] is False and
            max(row['handoffs'] for row in unknown) == 1 and
            state['unknown']['terminal_results'] == 1,
            'UNKNOWN terminal differs from ordinary pending')
    second = suite['cases'][1]
    mcp_source = next(row for row in mcp['cases'] if row['id'] == 'pending')
    wire = load(bytes.fromhex(mcp_source['input']['wire_hex']))
    require(second['input']['input'] == mcp_source['input'] and
            second['expected'] == {'verdict': 'ACCEPT', 'output': {
                'success': False, 'error': 'unavailable',
                'status': 'pending',
                'wire_hex': mcp_source['input']['wire_hex']}, 'effects': {}} and
            wire['isError'] is True and
            wire['structuredContent']['result']['status'] == 'pending' and
            len(wire['content']) == 1 and
            load(wire['content'][0]['text'].encode()) ==
            wire['structuredContent'],
            'signed pending MCP text and structured representation')
    return len(IDS)


if __name__ == '__main__':
    print(check())
