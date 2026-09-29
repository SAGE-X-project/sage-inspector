"""Bounded provisional-session observations for the six missing HPKE cases."""

from copy import deepcopy


SAMPLES = {
    'CST-05-01': {'first_record_ms': 299, 'deadline_ms': 300,
                  'signature_valid': True, 'aead_valid': True,
                  'nonce_reserved': True, 'sequence_reserved': True,
                  'establishments': 1, 'tool_effects': 0},
    'CST-05-02': {'first_record_ms': 300, 'deadline_ms': 300,
                  'establishments': 0, 'tool_effects': 0,
                  'owner_closed': True},
    'CST-05-03': {'signature_valid': False, 'aead_valid': True,
                  'replay_reservations': 0, 'establishments': 0,
                  'owner_state': 'PROVISIONAL'},
    'CST-05-04': {'identical_record_ids': ['record-1', 'record-1'],
                  'identical_accepted': 1,
                  'distinct_record_ids': ['record-2', 'record-3'],
                  'distinct_accepted': 2,
                  'establishments': 1, 'tool_effects': 0},
    'CST-05-05': {'signature_valid': True, 'aead_valid': True,
                  'replay_reservations': 1, 'establishments': 1,
                  'policy_allowed': False, 'encrypted_rejections': 1,
                  'tool_effects': 0},
    'CST-05-06': {'first_record_ms': 299, 'deadline_ms': 300,
                  'sequence': 7, 'signature_valid': True,
                  'aead_valid': True, 'establishments': 1,
                  'sequence_counter_reset': False},
}


def sample(ident):
    return deepcopy(SAMPLES[ident])


def check(ident, evidence):
    if ident not in SAMPLES or type(evidence) is not dict or \
            set(evidence) != set(SAMPLES[ident]) or \
            any(type(evidence[key]) is not type(value)
                for key, value in SAMPLES[ident].items()):
        return False
    if ident == 'CST-05-01':
        return (0 <= evidence['first_record_ms'] < evidence['deadline_ms'] and
                evidence['signature_valid'] and evidence['aead_valid'] and
                evidence['nonce_reserved'] and evidence['sequence_reserved'] and
                evidence['establishments'] == 1 and
                evidence['tool_effects'] == 0)
    if ident == 'CST-05-02':
        return (0 <= evidence['deadline_ms'] <=
                evidence['first_record_ms'] and
                evidence['establishments'] == evidence['tool_effects'] == 0 and
                evidence['owner_closed'])
    if ident == 'CST-05-03':
        return (not evidence['signature_valid'] and
                evidence['replay_reservations'] ==
                evidence['establishments'] == 0 and
                evidence['owner_state'] == 'PROVISIONAL')
    if ident == 'CST-05-04':
        return (len(evidence['identical_record_ids']) == 2 and
                len(set(evidence['identical_record_ids'])) == 1 and
                evidence['identical_accepted'] == 1 and
                len(evidence['distinct_record_ids']) == 2 and
                len(set(evidence['distinct_record_ids'])) == 2 and
                evidence['distinct_accepted'] == 2 and
                evidence['establishments'] == 1 and
                evidence['tool_effects'] == 0)
    if ident == 'CST-05-05':
        return (evidence['signature_valid'] and evidence['aead_valid'] and
                evidence['replay_reservations'] ==
                evidence['establishments'] ==
                evidence['encrypted_rejections'] == 1 and
                not evidence['policy_allowed'] and
                evidence['tool_effects'] == 0)
    return (0 <= evidence['first_record_ms'] < evidence['deadline_ms'] and
            evidence['sequence'] > 0 and
            evidence['signature_valid'] and evidence['aead_valid'] and
            evidence['establishments'] == 1 and
            not evidence['sequence_counter_reset'])
