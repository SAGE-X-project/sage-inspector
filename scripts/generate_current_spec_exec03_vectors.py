"""Project bounded intent checks into current, explicitly partial case fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
SOURCE = ROOT / 'vectors/0.10.0/guard-records.json'
IDS = tuple('EXEC-03-' + suffix for suffix in
            ('P', 'N01', 'N02', 'N03', 'N04', 'N05'))


def cases():
    historical = {row['id']: row for row in json.loads(SOURCE.read_text())['cases']}
    valid = historical['intent-valid']['input']
    bad_nonce = copy.deepcopy(valid)
    envelope = json.loads(bytes.fromhex(valid['envelope_hex']))
    envelope['intent']['nonce'] = 'bad'
    bad_nonce['envelope_hex'] = json.dumps(envelope, sort_keys=True,
                                           separators=(',', ':')).encode().hex()
    wrong_executor = copy.deepcopy(valid)
    wrong_executor['expected_recipient'] = valid['expected_issuer']
    oversize = historical['json-bytes-1048577']['input']
    return [
        ('EXEC-03-P', 'sage.guard.intent.verify', valid, 'ACCEPT', {'valid': True}),
        ('EXEC-03-N01', 'sage.guard.intent.verify',
         historical['intent-tampered']['input'], 'REJECT', {}),
        ('EXEC-03-N02', 'sage.guard.intent.verify',
         historical['intent-unknown-field']['input'], 'REJECT', {}),
        ('EXEC-03-N03', 'sage.guard.json.bounds', oversize, 'REJECT', {}),
        ('EXEC-03-N04', 'sage.guard.intent.verify', bad_nonce, 'REJECT', {}),
        ('EXEC-03-N05', 'sage.guard.intent.verify', wrong_executor, 'REJECT', {}),
    ]


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
             'scope': 'intent verifier and generic JSON size primitives; no outer HTTP binding, dispatch, or full case conformance claim',
             'cases': []}
    bindings_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(bindings_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, operation, inp, verdict, output in cases():
        expected = {'verdict': verdict, 'output': output, 'effects': {}}
        suite['cases'].append({'id': ident, 'operation': operation,
                               'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': {'operation': operation, 'input': inp},
                   'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec03-intents.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    bindings_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
