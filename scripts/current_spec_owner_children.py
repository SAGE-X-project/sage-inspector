"""Finite observations for the required MCP owner admission schedules.

The checks describe local inspection predicates, not deployed host evidence.
"""

GROUPS = {
    'generation': ('generation-policy', 'generation-component',
                   'generation-session'),
    'observation': ('observation-age-4999', 'observation-age-5000',
                    'observation-age-5001', 'observation-before-start'),
    'queue_failure': ('queue-capacity-race', 'queue-insert-failure'),
    'shared_close': ('shared-owner-close',),
    'fence': ('fence-close-success', 'fence-close-failure',
              'fence-close-uncertain'),
    'write_failure': ('unknown-write-failure',),
    'recovery_failure': ('recovery-conversion-failure',),
    'expiry': ('queue-expiry-before', 'queue-expiry-after'),
    'retirement': ('policy-retirement-invalidate-first',
                   'policy-retirement-claim-first',
                   'baseline-replacement-invalidate-first',
                   'baseline-replacement-claim-first'),
    'scheduler': ('scheduler-cancel-race', 'scheduler-stall'),
    'pool': ('reconnect-pool-bound',),
    'history': ('owner-history-1024',),
    'record_limit': ('session-record-limit-first',),
}
IDS = {ident for members in GROUPS.values() for ident in members}


def group(ident):
    return next(name for name, members in GROUPS.items() if ident in members)


def sample(ident):
    name = group(ident)
    if name == 'generation':
        return {'observed_generation': 1, 'current_generation': 2,
                'queue_admissions': 0, 'effects': 0,
                'identity_preserved': True, 'outcome': 'UNKNOWN'}
    if name == 'observation':
        age = (-1 if ident == 'observation-before-start' else
               int(ident.rsplit('-', 1)[1]))
        return {'started_ms': 1000, 'observed_ms': 1000 + age,
                'queue_admissions': 1 if 0 <= age <= 5000 else 0,
                'effects': 0, 'reservation_preserved': True}
    if name == 'queue_failure':
        return {'visible_queue_entries': 0, 'effects': 0,
                'ledger_identity_retained': True,
                'partial_worker_claims': 0}
    if name == 'shared_close':
        return {'owner_a_admissions': 0, 'owner_a_effects': 0,
                'owner_b_admissions': 1, 'owner_b_effects': 1,
                'global_retirement': False}
    if name == 'fence':
        return {'write_outcome': ident.rsplit('-', 1)[1].upper(),
                'queue_admissions': 0, 'effects': 0,
                'durable_evidence_retained': True}
    if name == 'write_failure':
        return {'scope_available': False,
                'exclusive_writer_retained': True,
                'queue_admissions': 0, 'effects': 0}
    if name == 'recovery_failure':
        return {'writer_ready': False, 'reconstructed_queue_entries': 0,
                'storage_isolated': True, 'effects': 0}
    if name == 'expiry':
        before = ident.endswith('-before')
        return {'expiry_seq': 1 if before else 2,
                'queue_insert_seq': None if before else 1,
                'queue_admissions': 0 if before else 1,
                'effects': 0 if before else 1,
                'reservation_preserved': True}
    if name == 'retirement':
        invalidate_first = ident.endswith('invalidate-first')
        return {'invalidation_seq': 1 if invalidate_first else 2,
                'worker_claim_seq': None if invalidate_first else 1,
                'entry_cancelled': invalidate_first,
                'effects': 0 if invalidate_first else 1,
                'pinned_old_instance': not invalidate_first}
    if name == 'scheduler':
        return ({'worker_claims': 0, 'cancellations': 1,
                 'cancelled_entry_effects': 0}
                if ident == 'scheduler-cancel-race' else
                {'occupied_slots': 2, 'worker_limit': 2,
                 'extra_work_admitted': 0})
    if name == 'pool':
        return {'worker_limit_before': 2, 'worker_limit_after': 2,
                'active_workers': 2, 'new_slots_before_completion': 0}
    if name == 'history':
        return {'retained_ids': 1024, 'next_id_admitted': False,
                'replacement_reset_count': 0}
    return {'session_record_limit': 512, 'owner_history_limit': 1024,
            'consumed_control_records': 2, 'first_denied_record': 512,
            'owner_closed': True}


def check(ident, evidence):
    if ident not in IDS or type(evidence) is not dict or \
            set(evidence) != set(sample(ident)) or \
            any(type(evidence[key]) is not type(value)
                for key, value in sample(ident).items()):
        return False
    name = group(ident)
    try:
        if name == 'generation':
            return (evidence['observed_generation'] <
                    evidence['current_generation'] and
                    evidence['queue_admissions'] == evidence['effects'] == 0 and
                    evidence['identity_preserved'] is True and
                    evidence['outcome'] in ('UNKNOWN', 'UNAVAILABLE'))
        if name == 'observation':
            age = evidence['observed_ms'] - evidence['started_ms']
            expected_age = (-1 if ident == 'observation-before-start' else
                            int(ident.rsplit('-', 1)[1]))
            return (age == expected_age and
                    evidence['queue_admissions'] ==
                    (1 if 0 <= age <= 5000 else 0) and
                    evidence['effects'] == 0 and
                    evidence['reservation_preserved'] is True)
        if name == 'queue_failure':
            return (evidence['visible_queue_entries'] == 0 and
                    evidence['effects'] == 0 and
                    evidence['ledger_identity_retained'] is True and
                    evidence['partial_worker_claims'] == 0)
        if name == 'shared_close':
            return (evidence['owner_a_admissions'] ==
                    evidence['owner_a_effects'] == 0 and
                    evidence['owner_b_admissions'] ==
                    evidence['owner_b_effects'] == 1 and
                    evidence['global_retirement'] is False)
        if name == 'fence':
            return (evidence['write_outcome'] ==
                    ident.rsplit('-', 1)[1].upper() and
                    evidence['queue_admissions'] == evidence['effects'] == 0 and
                    evidence['durable_evidence_retained'] is True)
        if name == 'write_failure':
            return (evidence['scope_available'] is False and
                    evidence['exclusive_writer_retained'] is True and
                    evidence['queue_admissions'] == evidence['effects'] == 0)
        if name == 'recovery_failure':
            return (evidence['writer_ready'] is False and
                    evidence['reconstructed_queue_entries'] == 0 and
                    evidence['storage_isolated'] is True and
                    evidence['effects'] == 0)
        if name == 'expiry':
            before = ident.endswith('-before')
            return (evidence['reservation_preserved'] is True and
                    (evidence['queue_insert_seq'] is None and
                     evidence['queue_admissions'] == evidence['effects'] == 0
                     if before else
                     0 <= evidence['queue_insert_seq'] <
                     evidence['expiry_seq'] and
                     evidence['queue_admissions'] == 1 and
                     evidence['effects'] in (0, 1)))
        if name == 'retirement':
            invalidate_first = ident.endswith('invalidate-first')
            return (evidence['invalidation_seq'] >= 0 and
                    (evidence['worker_claim_seq'] is None and
                     evidence['entry_cancelled'] is True and
                     evidence['effects'] == 0 and
                     evidence['pinned_old_instance'] is False
                     if invalidate_first else
                     0 <= evidence['worker_claim_seq'] <
                     evidence['invalidation_seq'] and
                     evidence['entry_cancelled'] is False and
                     evidence['pinned_old_instance'] is True and
                     evidence['effects'] in (0, 1)))
        if name == 'scheduler':
            return (evidence['worker_claims'] +
                    evidence['cancellations'] == 1 and
                    evidence['cancelled_entry_effects'] == 0
                    if ident == 'scheduler-cancel-race' else
                    0 <= evidence['occupied_slots'] ==
                    evidence['worker_limit'] <= 64 and
                    evidence['extra_work_admitted'] == 0)
        if name == 'pool':
            return (0 <= evidence['active_workers'] ==
                    evidence['worker_limit_before'] ==
                    evidence['worker_limit_after'] <= 64 and
                    evidence['new_slots_before_completion'] == 0)
        if name == 'history':
            return (evidence['retained_ids'] == 1024 and
                    evidence['next_id_admitted'] is False and
                    evidence['replacement_reset_count'] == 0)
        return (0 < evidence['session_record_limit'] <
                evidence['owner_history_limit'] == 1024 and
                evidence['consumed_control_records'] >= 2 and
                evidence['first_denied_record'] ==
                evidence['session_record_limit'] and
                evidence['owner_closed'] is True)
    except (TypeError, ValueError, KeyError):
        return False
