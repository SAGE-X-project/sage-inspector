"""Check HPKE-04 completion signature and pending-request fixtures."""

import base64
import hashlib
import hmac
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_hpke03_vectors import check as check_hpke03


IDS = ('HPKE-04-P', 'HPKE-04-N01', 'HPKE-04-N02',
       'HPKE-04-N03', 'HPKE-04-N04')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def binary(value, length):
    require(type(value) is str, 'HPKE-04 binary value type')
    data = base64.urlsafe_b64decode(value + '==')
    require(len(data) == length and
            base64.urlsafe_b64encode(data).decode().rstrip('=') == value,
            'HPKE-04 canonical binary field')
    return data


def check(root=ROOT):
    require(check_hpke03(root) == 5, 'HPKE-04 transcript and ACK provenance')
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'HPKE-04 fixture identity')
    primitives = {row['id']: row for row in load((root /
        'vectors/0.10.0/hpke-primitives.json').read_bytes())['cases']}
    schedule = {row['id']: row for row in load((root /
        'vectors/0.10.0/hpke-schedule.json').read_bytes())['cases']}
    valid = schedule['completion-valid']
    pending = valid['input']['pending']
    complete_raw = bytes.fromhex(valid['input']['completion_hex'])
    complete = load(complete_raw)
    initiation = load(bytes.fromhex(pending['initiation_hex']))
    require(complete_raw == canonical(complete) and
            set(complete) == {'v', 'task', 'transcript', 'ackTagB64', 'sigB64'} and
            complete['v'] == '0.10.0' and
            complete['task'] == 'hpke/complete@0.10.0' and
            set(complete['transcript']) == set(initiation) | {'ephS', 'kid'} and
            all(complete['transcript'][key] == value for
                key, value in initiation.items()) and
            len(binary(complete['ackTagB64'], 32)) == 32 and
            len(binary(complete['sigB64'], 64)) == 64,
            'HPKE-04 closed completion and exact initiation echo')
    transcript = canonical(complete['transcript'])
    th = hashlib.sha256(transcript).digest()
    schedule0 = schedule['schedule-0']['expected']['output']
    exporter = bytes.fromhex(schedule0['exporter_hex'])
    shared = bytes.fromhex(schedule0['ss_e2e_hex'])
    prk = hmac.digest(th, exporter + shared, 'sha256')
    seed = hmac.digest(prk, b'sage-hpke-combiner|0.10.0' + th + b'\x01', 'sha256')
    ack_key = hmac.digest(seed, b'sage-hpke-ack|0.10.0' + th + b'\x01', 'sha256')
    require(hmac.digest(ack_key, th, 'sha256') ==
            binary(complete['ackTagB64'], 32) and
            transcript.hex() == schedule0['transcript_hex'],
            'HPKE-04 independent transcript acknowledgement')
    unsigned = dict(complete)
    del unsigned['sigB64']
    message = b'sage-hpke-complete|0.10.0\n' + canonical(unsigned)
    anchor = primitives['completion-signature-0']
    require(anchor['operation'] == 'signature.verify' and
            anchor['input'] == {'algorithm': 'ed25519',
                'public_key_hex': pending['responder_signing_public_hex'],
                'message_hex': message.hex(),
                'signature_hex': binary(complete['sigB64'], 64).hex()} and
            anchor['expected'] == {'verdict': 'ACCEPT',
                                    'output': {'valid': True}} and
            fixtures['HPKE-04-P']['input'] == {
                'operation': 'signature.verify', 'input': anchor['input']} and
            fixtures['HPKE-04-P']['expected'] == {
                'verdict': 'ACCEPT', 'output': {'valid': True}, 'effects': {}},
            'HPKE-04 exact inner signature bytes')

    changed = load(bytes.fromhex(fixtures['HPKE-04-N01']['input']['input']
                                 ['completion_hex']))
    changed_kid = '33333333-3333-4333-8333-333333333339'
    require(changed == dict(complete,
                transcript=dict(complete['transcript'], kid=changed_kid)) and
            fixtures['HPKE-04-N01']['input'] == {
                'operation': 'sage.hpke.complete.verify',
                'input': dict(valid['input'],
                    completion_hex=canonical(changed).hex())},
            'HPKE-04 changed signed kid')
    wrong_ack = schedule['wrong-ack']
    wrong = load(bytes.fromhex(wrong_ack['input']['completion_hex']))
    require(wrong['transcript'] == complete['transcript'] and
            wrong['ackTagB64'] != complete['ackTagB64'] and
            wrong['sigB64'] != complete['sigB64'] and
            fixtures['HPKE-04-N02']['input'] == {
                'operation': wrong_ack['operation'], 'input': wrong_ack['input']},
            'HPKE-04 signed wrong ACK')
    other = schedule['different-pending-request']
    require(other['input']['completion_hex'] == valid['input']['completion_hex'] and
            other['input']['pending']['initiation_hex'] != pending['initiation_hex'] and
            fixtures['HPKE-04-N03']['input'] == {
                'operation': other['operation'], 'input': other['input']},
            'HPKE-04 valid completion from another pending request')
    for ident in IDS[1:4]:
        require(fixtures[ident]['expected'] == {
            'verdict': 'REJECT', 'output': {},
            'effects': {'sessions_created': 0, 'protected_dispatches': 0}},
            'HPKE-04 zero protected effects: ' + ident)
    bad = load(bytes.fromhex(schedule['invalid-signature']['input']
                              ['completion_hex']))
    bad_signature = dict(anchor['input'],
                         signature_hex=binary(bad['sigB64'], 64).hex())
    require(bad['transcript'] == complete['transcript'] and
            bad['ackTagB64'] == complete['ackTagB64'] and
            bad_signature['signature_hex'] == '00' * 64 and
            fixtures['HPKE-04-N04']['input'] == {
                'operation': 'signature.verify', 'input': bad_signature} and
            fixtures['HPKE-04-N04']['expected'] == {
                'verdict': 'REJECT', 'output': {}, 'effects': {}},
            'HPKE-04 bad inner signature isolation')
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-04 completion fixtures:', check())
