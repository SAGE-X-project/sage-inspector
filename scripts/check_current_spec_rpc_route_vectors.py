"""Audit control and excluded RPC routes against pinned public bytes."""

import json

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_rpc_route_vectors import IDS, SPEC, cases


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/exec-rpc-routes.json').read_bytes())
    source = root / 'vectors/0.10.0/guard-rpc.json'
    rpc = load(source.read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['rpc_bytes_sha256'] == sha(source.read_bytes()) and
            [row['id'] for row in suite['cases']] == [ident for ident, _ in IDS],
            'pinned RPC route source')
    requests = {row['id']: row for row in rpc['requests']}
    for row, (ident, inp, expected), (_, name) in zip(suite['cases'], cases(), IDS):
        payload = {'operation': 'sage.guard.rpc.route_pair', 'input': inp}
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (root / relative).read_bytes()
        require(row == {'id': ident, 'input': payload, 'expected': expected} and
                load(raw) == {'schema_version': 1, 'spec_revision': SPEC,
                              'id': ident, 'track': 'runtime',
                              'input': payload, 'expected': expected} and
                any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': relative,
                                'fixture_sha256': sha(raw),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'RPC partial binding')
        require(inp['control_wire_hex'] == requests['valid']['wire_hex'] and
                inp['candidate_wire_hex'] == requests[name]['wire_hex'] and
                requests['valid']['accept'] is True and
                requests[name]['accept'] is False and
                inp['configuration'] == rpc['input'] and
                inp['outer_id'] == rpc['id'],
                'independent control and excluded route')
        control = load(bytes.fromhex(inp['control_wire_hex']))
        candidate = load(bytes.fromhex(inp['candidate_wire_hex']))
        require(control['method'] == 'tools/call' and
                control['params']['name'] == 'sage_secure_call' and
                (('id' not in candidate) if name == 'notification' else
                 candidate['params']['name'] != 'sage_secure_call'),
                'notification or direct-tool route')
    return len(IDS)


if __name__ == '__main__':
    print(check())
