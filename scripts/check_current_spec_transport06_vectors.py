"""Check declarative WebSocket and local-adapter boundary scenarios."""

import base64
import copy
import json

from current_spec_catalog import ROOT, load, require, sha
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-06-P', 'TRANSPORT-06-N01', 'TRANSPORT-06-N02',
       'TRANSPORT-06-N03', 'TRANSPORT-06-N04')
EXTRAS = ('local-signed-control', 'wrong-recipient-on-trusted-wss',
          'unsigned-on-trusted-wss', 'exact-frame-limit')
SOURCE = 'vectors/0.10.0/transport06-scenarios.json'
LIMIT = 16 * 1024 * 1024


def signed(envelope, public):
    if 'signature' not in envelope:
        return False
    unsigned = copy.deepcopy(envelope)
    signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
    message = b'sage-wire-request|0.10.0\n' + json.dumps(
        unsigned, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    return verified(public, signature, message)


def model(row):
    """Unit-only gate; does not emit frames or invoke a receiving core."""
    if 'fragment_lengths' in row:
        require(row['fragment_lengths'] and
                all(type(value) is int and value >= 0
                    for value in row['fragment_lengths']),
                'compact fragment lengths')
        return sum(row['fragment_lengths']) <= LIMIT
    if row['carrier'] == 'websocket':
        if not row['tls_authenticated'] or row['compression'] or \
                row['message_kind'] != 'text':
            return False
        raw = b''.join(bytes.fromhex(part) for part in row['fragments_hex'])
        if len(raw) > LIMIT:
            return False
    else:
        require(row['carrier'] == 'local', 'known local adapter carrier')
        if not row['trusted_hook']:
            return False
        raw = bytes.fromhex(row['envelope_hex'])
    try:
        envelope = load(raw)
    except (UnicodeError, ValueError):
        return False
    if type(envelope) is not dict:
        return False
    public = bytes.fromhex(row['trusted_public_key_hex'])
    return (envelope.get('recipient') == row['expected_recipient'] and
            signed(envelope, public))


def check(root=ROOT):
    source_raw = (root / 'vectors/0.10.0/http-boundaries.json').read_bytes()
    source = {row['id']: row for row in load(source_raw)['cases']}
    suite_raw = (root / SOURCE).read_bytes()
    suite = load(suite_raw)
    require(suite['schema_version'] == 1 and
            suite['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            suite['source_sha256'] == sha(source_raw) and
            tuple(row['id'] for row in suite['cases']) == IDS and
            tuple(row['name'] for row in suite['supplemental']) == EXTRAS,
            'TRANSPORT-06 source and case identity')
    control = bytes.fromhex(source['valid-request']['input']['request_hex']
                            ).split(b'\r\n\r\n', 1)[1]
    envelope = load(control)
    unsigned = copy.deepcopy(envelope)
    unsigned.pop('signature')
    unsigned_raw = json.dumps(unsigned, sort_keys=True,
                              separators=(',', ':')).encode()
    public = bytes.fromhex(source['valid-request']['input']['public_key_hex'])
    require(signed(envelope, public) and
            envelope['recipient'] ==
                source['valid-request']['input']['expected_recipient'],
            'independently signed WebSocket source envelope')
    rows = {row['id']: row for row in suite['cases']}
    positive = rows['TRANSPORT-06-P']
    require(positive['carrier'] == 'websocket' and
            positive['tls_authenticated'] is True and
            positive['message_kind'] == 'text' and
            positive['compression'] is False and
            len(positive['fragments_hex']) == 2 and
            b''.join(bytes.fromhex(x) for x in positive['fragments_hex']) ==
                control and model(positive),
            'authenticated fragmented text control')
    compressed = rows['TRANSPORT-06-N01']
    binary = rows['TRANSPORT-06-N02']
    require(compressed['compression'] is True and
            binary['message_kind'] == 'binary' and
            bytes.fromhex(compressed['fragments_hex'][0]) == control and
            bytes.fromhex(binary['fragments_hex'][0]) == control,
            'valid signed content with prohibited WebSocket framing')
    oversized = rows['TRANSPORT-06-N03']
    require(oversized['fragment_lengths'] == [LIMIT // 2, LIMIT // 2 + 1]
            and oversized['fill_byte_hex'] == '78' and
            sum(oversized['fragment_lengths']) == LIMIT + 1 and
            'fragments_hex' not in oversized,
            'compact cumulative 16 MiB plus one boundary')
    local = rows['TRANSPORT-06-N04']
    require(local['carrier'] == 'local' and local['trusted_hook'] is True and
            bytes.fromhex(local['envelope_hex']) == unsigned_raw and
            not signed(load(unsigned_raw), public),
            'trusted local path cannot admit unsigned envelope')
    extra = {row['name']: row for row in suite['supplemental']}
    require(bytes.fromhex(extra['local-signed-control']['envelope_hex']) ==
            control and extra['local-signed-control']['trusted_hook'] is True and
            extra['wrong-recipient-on-trusted-wss']['expected_recipient'] ==
            envelope['did'] and
            bytes.fromhex(extra['wrong-recipient-on-trusted-wss']
                          ['fragments_hex'][0]) == control and
            bytes.fromhex(extra['unsigned-on-trusted-wss']
                          ['fragments_hex'][0]) == unsigned_raw and
            extra['exact-frame-limit']['fragment_lengths'] ==
                [LIMIT // 2, LIMIT // 2],
            'signed local control and trusted-WebSocket counterexamples')
    for row in (*suite['cases'], *suite['supplemental']):
        predicted = 'ACCEPT' if model(row) else 'REJECT'
        expected = row.get('expected', row.get('expected_size_gate'))
        require(predicted == expected,
                'unit-only frame and signature gate: ' +
                row.get('id', row.get('name')))
    for ident in IDS:
        row = rows[ident]
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] ==
                    ('sage.transport.local.receive' if ident == IDS[-1] else
                     'sage.transport.ws.receive') and
                fixture['input']['input'] == row and
                fixture['expected'] == {
                    'verdict': row['expected'],
                    'output': {'valid': True} if ident == IDS[0] else {},
                    'effects': {'application_dispatches':
                                1 if ident == IDS[0] else 0}},
                'TRANSPORT-06 runtime fixture contract: ' + ident)
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('16 MiB limit applies during reassembly' in spec and
            'binary messages' in spec and 'per-message compression' in spec and
            'verification in an unavoidable trusted execution path' in spec,
            'pinned TRANSPORT-06 carrier and trust rules')
    return len(IDS), len(EXTRAS)


if __name__ == '__main__':
    print('Verified TRANSPORT-06 cases and controls:', check())
