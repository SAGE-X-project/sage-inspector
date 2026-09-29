"""Bind guarded RPC route exclusions to public inert requests."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = (('EXEC-08-N04', 'notification'),
       ('EXEC-08-N05', 'direct-tool'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    source = json.loads((ROOT / 'vectors/0.10.0/guard-rpc.json').read_text())
    requests = {row['id']: row for row in source['requests']}
    for ident, name in IDS:
        inp = {'configuration': source['input'], 'outer_id': source['id'],
               'mcp_version': '2025-06-18',
               'control_wire_hex': requests['valid']['wire_hex'],
               'candidate_wire_hex': requests[name]['wire_hex']}
        expected = {'verdict': 'REJECT',
                    'output': {'control': {'accepted': True, 'committed': True,
                                           'effects': 1,
                                           'journal_states': ['RESERVED', 'EXECUTING']},
                               'candidate': {'accepted': False, 'committed': False,
                                             'effects': 0, 'journal_states': []}},
                    'effects': {'candidate_dispatch': 0}}
        yield ident, inp, expected


def main():
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in {ident for ident, _ in IDS}]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'rpc_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-rpc.json').read_bytes()),
             'scope': 'bounded guarded RPC parser and inert dispatch only; no host route isolation or model hook claim',
             'cases': []}
    for ident, inp, expected in cases():
        payload = {'operation': 'sage.guard.rpc.route_pair', 'input': inp}
        suite['cases'].append({'id': ident, 'input': payload,
                               'expected': expected})
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (json.dumps({'schema_version': 1, 'spec_revision': SPEC,
                           'id': ident, 'track': 'runtime',
                           'input': payload, 'expected': expected}, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-rpc-routes.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
