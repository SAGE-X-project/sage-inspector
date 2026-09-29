"""Independently audit request header projection and routing boundaries."""

import copy

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table06-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-06-P', 'TABLE-06-N01', 'TABLE-06-N02')
HASHES = {
    'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
    'spec/03-rfc9421.md': 'ca6b85e12a0b0e1a4f28b4eb2a9b677d29e2fd2abe9691d1ee30bfa14ee858c9',
    'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb',
}
SENDER = 'did:sage:web:agents.example.com:alice'
MESSAGE_ID = '123e4567-e89b-42d3-a456-426614174000'
CONTEXT_ID = '123e4567-e89b-42d3-a456-426614174001'
TASK_ID = '123e4567-e89b-42d3-a456-426614174002'
COVERED = ['@method', '@target-uri', '@authority', 'content-type',
           'content-digest', 'x-sage-did', 'x-sage-version']
PROJECTIONS = {'X-SAGE-Message-ID': 'id',
               'X-SAGE-Context-ID': 'context_id',
               'X-SAGE-Task-ID': 'task_id'}


def decision(inp):
    if (type(inp) is not dict or set(inp) != {
            'direction', 'body_projection', 'headers', 'signature_fields_present',
            'signature_parameters', 'covered_components', 'routing'} or
            inp['direction'] != 'request'):
        return 'REJECT'
    body, headers, params, route = (inp['body_projection'], inp['headers'],
                                   inp['signature_parameters'], inp['routing'])
    if (type(body) is not dict or type(headers) is not dict or
            type(params) is not dict or type(route) is not dict):
        return 'REJECT'
    required_body = {'version', 'did', 'kid', 'id', 'created', 'expires', 'nonce'}
    if (not required_body <= set(body) or
            set(body) - required_body - {'context_id', 'task_id'} or
            any(body[name] is None for name in ('context_id', 'task_id') if name in body) or
            not {'X-SAGE-Version', 'X-SAGE-DID', 'Content-Type'} <= set(headers) or
            set(headers) - {'X-SAGE-Version', 'X-SAGE-DID', 'Content-Type',
                            *PROJECTIONS} or
            inp['signature_fields_present'] != [
                'Signature-Input', 'Signature', 'Content-Digest'] or
            inp['covered_components'] != COVERED):
        return 'REJECT'
    if (body['version'] != '0.10.0' or headers['X-SAGE-Version'] != body['version'] or
            type(body['did']) is not str or
            headers['X-SAGE-DID'] != body['did'] or
            headers['Content-Type'] != 'application/json' or
            type(body['kid']) is not str or
            body['kid'].count('#') != 1 or
            body['kid'].split('#')[0] != body['did']):
        return 'REJECT'
    if (set(params) != {'keyid', 'created', 'expires', 'nonce'} or
            params != {name: body['kid' if name == 'keyid' else name]
                       for name in ('keyid', 'created', 'expires', 'nonce')}):
        return 'REJECT'
    if any(member not in body or headers[header] != body[member]
           for header, member in PROJECTIONS.items() if header in headers):
        return 'REJECT'
    if (set(route) != {'source', 'message_id'} or
            route['source'] != 'verified-body' or
            route['message_id'] != body['id']):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['source_sha256'] == HASHES and
            all(manifest['source_sha256'][path] == digest for path, digest in HASHES.items()) and
            data['scope'] == 'synthetic request header/body projection; no signature, digest, response binding, replay, or trusted endpoint verification' and
            tuple(row['id'] for row in data['cases']) == IDS,
            'pinned TABLE-06 sources and bounded cases')
    good, mismatch, unsigned = [row['input'] for row in data['cases']]
    expected_body = {
        'version': '0.10.0', 'did': SENDER, 'kid': SENDER + '#signing-1',
        'id': MESSAGE_ID, 'context_id': CONTEXT_ID, 'task_id': TASK_ID,
        'created': 100, 'expires': 200, 'nonce': 'AAAAAAAAAAAAAAAAAAAAAA'}
    require(good == {
        'direction': 'request', 'body_projection': expected_body,
        'headers': {'X-SAGE-Version': '0.10.0', 'X-SAGE-DID': SENDER,
                    'X-SAGE-Message-ID': MESSAGE_ID,
                    'X-SAGE-Context-ID': CONTEXT_ID,
                    'X-SAGE-Task-ID': TASK_ID,
                    'Content-Type': 'application/json'},
        'signature_fields_present': ['Signature-Input', 'Signature', 'Content-Digest'],
        'signature_parameters': {'keyid': expected_body['kid'],
                                 'created': 100, 'expires': 200,
                                 'nonce': expected_body['nonce']},
        'covered_components': COVERED,
        'routing': {'source': 'verified-body', 'message_id': MESSAGE_ID}} and
            decision(good) == 'ACCEPT',
            'exact mandatory request headers and optional body projections')
    require(mismatch == dict(good, headers=dict(good['headers'],
                                              **{'X-SAGE-Context-ID': TASK_ID})) and
            unsigned == dict(good, routing={'source': 'header-projection',
                                             'message_id': MESSAGE_ID}),
            'isolated header/body mismatch and unsigned routing defects')
    for index, row in enumerate(data['cases']):
        ident = row['id']
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {'message_id': MESSAGE_ID} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(decision(row['input']) == expected['verdict'] and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.http.headers.binding.check',
                                      'input': row['input']}, 'expected': expected},
                'TABLE-06 case contract: ' + ident)
    controls = []
    optional_absent = copy.deepcopy(good)
    for header in PROJECTIONS:
        del optional_absent['headers'][header]
    controls.append(('optional-projections-absent', optional_absent, 'ACCEPT'))
    for name, path, value in (
        ('message-id-mismatch', ('headers', 'X-SAGE-Message-ID'), TASK_ID),
        ('task-id-mismatch', ('headers', 'X-SAGE-Task-ID'), CONTEXT_ID),
        ('missing-context-body', ('body_projection', 'context_id'), None),
        ('version-mismatch', ('headers', 'X-SAGE-Version'), '0.9.0'),
        ('did-mismatch', ('headers', 'X-SAGE-DID'), 'did:sage:web:agents.example.com:bob'),
        ('keyid-mismatch', ('signature_parameters', 'keyid'), SENDER + '#other'),
        ('missing-did-header', ('headers', 'X-SAGE-DID'), None),
        ('missing-signature-field', ('signature_fields_present',),
         ['Signature-Input', 'Content-Digest']),
        ('missing-content-digest', ('signature_fields_present',),
         ['Signature-Input', 'Signature']),
        ('coverage-omits-version', ('covered_components',), COVERED[:-1]),
        ('coverage-reordered', ('covered_components',), COVERED[::-1]),
        ('header-route', ('routing', 'source'), 'header-projection'),
        ('wrong-route-id', ('routing', 'message_id'), TASK_ID),
        ('parameterized-content-type', ('headers', 'Content-Type'),
         'application/json; charset=utf-8'),
        ('removed-meta-projection', ('headers', 'X-SAGE-Meta-Role'), 'admin'),
        ('null-optional-projection', ('headers', 'X-SAGE-Task-ID'), None),
        ('null-optional-body', ('body_projection', 'task_id'), None),
    ):
        changed = copy.deepcopy(good)
        node = changed
        for part in path[:-1]:
            node = node[part]
        if value is None and name not in ('null-optional-projection', 'null-optional-body'):
            del node[path[-1]]
        else:
            node[path[-1]] = value
        controls.append((name, changed, 'REJECT'))
    require(all(decision(inp) == verdict for _, inp, verdict in controls),
            'independent presence, equality, coverage, and routing controls')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['track'] == 'runtime' and
                    binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), len(controls)


if __name__ == '__main__':
    print(check())
