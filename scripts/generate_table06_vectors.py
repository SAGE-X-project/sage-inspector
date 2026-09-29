"""Generate bounded transport header binding fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-06-P', 'TABLE-06-N01', 'TABLE-06-N02')
SENDER = 'did:sage:web:agents.example.com:alice'
MESSAGE_ID = '123e4567-e89b-42d3-a456-426614174000'
CONTEXT_ID = '123e4567-e89b-42d3-a456-426614174001'
TASK_ID = '123e4567-e89b-42d3-a456-426614174002'
COMPONENTS = ['@method', '@target-uri', '@authority', 'content-type',
              'content-digest', 'x-sage-did', 'x-sage-version']


def main():
    body = {'version': '0.10.0', 'did': SENDER,
            'kid': SENDER + '#signing-1',
            'id': MESSAGE_ID, 'context_id': CONTEXT_ID, 'task_id': TASK_ID,
            'created': 100, 'expires': 200, 'nonce': 'AAAAAAAAAAAAAAAAAAAAAA'}
    good = {
        'direction': 'request', 'body_projection': body,
        'headers': {
            'X-SAGE-Version': '0.10.0', 'X-SAGE-DID': SENDER,
            'X-SAGE-Message-ID': MESSAGE_ID,
            'X-SAGE-Context-ID': CONTEXT_ID,
            'X-SAGE-Task-ID': TASK_ID,
            'Content-Type': 'application/json',
        },
        'signature_fields_present': ['Signature-Input', 'Signature', 'Content-Digest'],
        'signature_parameters': {'keyid': body['kid'], 'created': 100,
                                 'expires': 200, 'nonce': body['nonce']},
        'covered_components': COMPONENTS,
        'routing': {'source': 'verified-body', 'message_id': MESSAGE_ID},
    }
    mismatch = copy.deepcopy(good)
    mismatch['headers']['X-SAGE-Context-ID'] = TASK_ID
    unsigned_route = copy.deepcopy(good)
    unsigned_route['routing']['source'] = 'header-projection'
    rows = [
        ('TABLE-06-P', good, 'ACCEPT', 'required headers and optional projections match verified body'),
        ('TABLE-06-N01', mismatch, 'REJECT', 'context header disagrees with body'),
        ('TABLE-06-N02', unsigned_route, 'REJECT', 'unsigned projection used for routing'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'message_id': MESSAGE_ID} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.http.headers.binding.check',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': {
                 'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
                 'spec/03-rfc9421.md': 'ca6b85e12a0b0e1a4f28b4eb2a9b677d29e2fd2abe9691d1ee30bfa14ee858c9',
                 'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb'},
             'scope': 'synthetic request header/body projection; no signature, digest, response binding, replay, or trusted endpoint verification',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/table06-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
