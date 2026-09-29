"""Generate compact local WebSocket and adapter scenarios from a signed wire."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/http-boundaries.json'
OUTPUT = ROOT / 'vectors/0.10.0/transport06-scenarios.json'
LIMIT = 16 * 1024 * 1024


def main():
    source = SOURCE.read_bytes()
    row = next(case for case in json.loads(source)['cases']
               if case['id'] == 'valid-request')
    envelope = bytes.fromhex(row['input']['request_hex']).split(b'\r\n\r\n', 1)[1]
    unsigned = json.loads(envelope)
    del unsigned['signature']
    unsigned = json.dumps(unsigned, sort_keys=True,
                          separators=(',', ':')).encode()
    common = {'expected_recipient': row['input']['expected_recipient'],
              'trusted_public_key_hex': row['input']['public_key_hex'],
              'connection_url': 'wss://agent.example/messages'}
    cases = [
        dict(id='TRANSPORT-06-P', carrier='websocket', tls_authenticated=True,
             message_kind='text', compression=False,
             fragments_hex=[envelope[:11].hex(), envelope[11:].hex()],
             expected='ACCEPT', **common),
        dict(id='TRANSPORT-06-N01', carrier='websocket', tls_authenticated=True,
             message_kind='text', compression=True,
             fragments_hex=[envelope.hex()], expected='REJECT', **common),
        dict(id='TRANSPORT-06-N02', carrier='websocket', tls_authenticated=True,
             message_kind='binary', compression=False,
             fragments_hex=[envelope.hex()], expected='REJECT', **common),
        dict(id='TRANSPORT-06-N03', carrier='websocket', tls_authenticated=True,
             message_kind='text', compression=False,
             fragment_lengths=[LIMIT // 2, LIMIT // 2 + 1],
             fill_byte_hex='78', expected='REJECT', **common),
        dict(id='TRANSPORT-06-N04', carrier='local', tls_authenticated=None,
             message_kind='json', compression=None, trusted_hook=True,
             envelope_hex=unsigned.hex(), expected='REJECT', **common),
    ]
    extras = [
        dict(name='local-signed-control', carrier='local', trusted_hook=True,
             envelope_hex=envelope.hex(), expected='ACCEPT', **common),
        dict(name='wrong-recipient-on-trusted-wss', carrier='websocket',
             tls_authenticated=True, message_kind='text', compression=False,
             fragments_hex=[envelope.hex()],
             expected_recipient=json.loads(envelope)['did'],
             trusted_public_key_hex=common['trusted_public_key_hex'],
             connection_url=common['connection_url'], expected='REJECT'),
        dict(name='unsigned-on-trusted-wss', carrier='websocket',
             tls_authenticated=True, message_kind='text', compression=False,
             fragments_hex=[unsigned.hex()], expected='REJECT', **common),
        dict(name='exact-frame-limit', carrier='websocket',
             fragment_lengths=[LIMIT // 2, LIMIT // 2],
             expected_size_gate='ACCEPT'),
    ]
    suite = {'schema_version': 1,
             'spec_revision': '5bcf511e604579afa63f434013447f44b6858828',
             'source_sha256': hashlib.sha256(source).hexdigest(),
             'scope': 'declarative local framing and signature expectations; no oversized payload materialized or network traffic sent',
             'cases': cases, 'supplemental': extras}
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    print('Generated', len(cases), 'TRANSPORT-06 cases and', len(extras), 'controls')


if __name__ == '__main__':
    main()
