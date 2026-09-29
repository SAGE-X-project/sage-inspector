"""Bounded local decisions for MCP owner publication and exchange cases.

These predicates classify structured host observations. They do not establish
that a deployed host supplied complete or independent observations.
"""

from copy import deepcopy


SAMPLES = {
    'madd-mutable-buffer': {
        'captured_sha256': 'a' * 64, 'handoff_sha256': 'a' * 64,
        'caller_buffer_changed': True, 'handoff_rejected': False},
    'madd-synchronous-completion': {
        'barrier_install_seq': 1, 'callback_seq': 2,
        'publication_seq': 3, 'reentrant_publications': 0},
    'madd-duplicate-completion': {
        'completion_operation_ids': ['op-1', 'op-1'],
        'phase_publications': 1, 'output_count': 1,
        'protected_effects': 0},
    'madd-old-incarnation': {
        'retired_owner_id': 'owner-1', 'new_owner_id': 'owner-2',
        'callback_owner_id': 'owner-1', 'new_owner_mutations': 0,
        'readiness_transfers': 0},
    'madd-bounded-cancellation': {
        'before_admission_effects': 0, 'after_admission_claimed_rollback': False,
        'worker_limit': 2, 'workers_retained': 2},
    'madd-history-capacity': {
        'retained_ids': 1024, 'next_id_accepted': False,
        'replacement_replenished': False},
    'madd-close-before-handoff': {
        'close_seq': 2, 'queue_insert_seq': None,
        'queue_admissions': 0, 'effects': 0},
    'madd-close-after-handoff': {
        'close_seq': 3, 'queue_insert_seq': 2,
        'queue_admissions': 1, 'admission_retained': True},
    'madd-cross-language-setup': {
        'verified_pairs': ['go-go', 'go-rust', 'rust-go', 'rust-rust'],
        'protected_exchanges': 4, 'independent_implementations': 2},
    'madd-restart-consumption': {
        'old_owner_id': 'owner-1', 'new_owner_id': 'owner-2',
        'old_result_consumed': True, 'redeliveries': 0,
        'stale_callback_mutations': 0},
    'merrata-local-single-flight': {
        'first_slot_occupied': True, 'second_id_reservations': 0,
        'second_signatures': 0, 'second_ledger_reservations': 0,
        'first_exchange_retained': True},
    'merrata-server-overlap': {
        'history_before': 1, 'history_after': 2,
        'second_guard_reservations': 0, 'second_queue_insertions': 0,
        'owner_closed': True},
    'merrata-deferred-frame': {
        'first_send_success_seq': 2, 'deferred_auth_seq': 3,
        'deferred_route_seq': 4, 'deferred_frames': 1},
    'merrata-pending-followup': {
        'first_inner_id': 'inner-1', 'next_inner_id': 'inner-2',
        'first_outer_id': 'outer-1', 'next_outer_id': 'outer-2',
        'signed_call_id_before': 'call-1',
        'signed_call_id_after': 'call-1', 'slot_released': True},
    'merrata-deadline-close': {
        'owner_closed': True, 'result_consumptions': 0,
        'slot_transfers': 0, 'redispatches': 0,
        'claimed_rollbacks': 0},
    'merrata-shared-owners': {
        'owner_a_slots': 1, 'owner_b_slots': 1,
        'shared_worker_limit': 2, 'shared_workers_active': 2,
        'extra_work_admitted': 0},
}


def sample(ident):
    return deepcopy(SAMPLES[ident])


def check(ident, evidence):
    if ident not in SAMPLES or type(evidence) is not dict or \
            set(evidence) != set(SAMPLES[ident]) or \
            any(type(evidence[key]) is not type(value)
                for key, value in SAMPLES[ident].items()):
        return False
    try:
        if ident == 'madd-mutable-buffer':
            return (evidence['caller_buffer_changed'] is True and
                    evidence['captured_sha256'] == evidence['handoff_sha256'] and
                    evidence['handoff_rejected'] is False)
        if ident == 'madd-synchronous-completion':
            return (0 <= evidence['barrier_install_seq'] <
                    evidence['callback_seq'] < evidence['publication_seq'] and
                    evidence['reentrant_publications'] == 0)
        if ident == 'madd-duplicate-completion':
            return (len(evidence['completion_operation_ids']) == 2 and
                    len(set(evidence['completion_operation_ids'])) == 1 and
                    evidence['phase_publications'] == 1 and
                    evidence['output_count'] == 1 and
                    evidence['protected_effects'] == 0)
        if ident == 'madd-old-incarnation':
            return (evidence['retired_owner_id'] != evidence['new_owner_id'] and
                    evidence['callback_owner_id'] == evidence['retired_owner_id'] and
                    evidence['new_owner_mutations'] == 0 and
                    evidence['readiness_transfers'] == 0)
        if ident == 'madd-bounded-cancellation':
            return (evidence['before_admission_effects'] == 0 and
                    evidence['after_admission_claimed_rollback'] is False and
                    0 <= evidence['workers_retained'] <=
                    evidence['worker_limit'] <= 64)
        if ident == 'madd-history-capacity':
            return (evidence['retained_ids'] == 1024 and
                    evidence['next_id_accepted'] is False and
                    evidence['replacement_replenished'] is False)
        if ident == 'madd-close-before-handoff':
            return (evidence['close_seq'] >= 0 and
                    evidence['queue_insert_seq'] is None and
                    evidence['queue_admissions'] == 0 and
                    evidence['effects'] == 0)
        if ident == 'madd-close-after-handoff':
            return (0 <= evidence['queue_insert_seq'] <
                    evidence['close_seq'] and
                    evidence['queue_admissions'] == 1 and
                    evidence['admission_retained'] is True)
        if ident == 'madd-cross-language-setup':
            return (set(evidence['verified_pairs']) ==
                    {'go-go', 'go-rust', 'rust-go', 'rust-rust'} and
                    len(evidence['verified_pairs']) == 4 and
                    evidence['protected_exchanges'] == 4 and
                    evidence['independent_implementations'] == 2)
        if ident == 'madd-restart-consumption':
            return (evidence['old_owner_id'] != evidence['new_owner_id'] and
                    evidence['old_result_consumed'] is True and
                    evidence['redeliveries'] == 0 and
                    evidence['stale_callback_mutations'] == 0)
        if ident == 'merrata-local-single-flight':
            return (evidence['first_slot_occupied'] is True and
                    evidence['second_id_reservations'] == 0 and
                    evidence['second_signatures'] == 0 and
                    evidence['second_ledger_reservations'] == 0 and
                    evidence['first_exchange_retained'] is True)
        if ident == 'merrata-server-overlap':
            return (evidence['history_after'] ==
                    evidence['history_before'] + 1 and
                    evidence['second_guard_reservations'] == 0 and
                    evidence['second_queue_insertions'] == 0 and
                    evidence['owner_closed'] is True)
        if ident == 'merrata-deferred-frame':
            return (0 <= evidence['first_send_success_seq'] <
                    evidence['deferred_auth_seq'] <
                    evidence['deferred_route_seq'] and
                    evidence['deferred_frames'] == 1)
        if ident == 'merrata-pending-followup':
            return (evidence['first_inner_id'] != evidence['next_inner_id'] and
                    evidence['first_outer_id'] != evidence['next_outer_id'] and
                    evidence['signed_call_id_before'] ==
                    evidence['signed_call_id_after'] and
                    evidence['slot_released'] is True)
        if ident == 'merrata-deadline-close':
            return (evidence['owner_closed'] is True and
                    all(evidence[key] == 0 for key in
                        ('result_consumptions', 'slot_transfers',
                         'redispatches', 'claimed_rollbacks')))
        return (evidence['owner_a_slots'] == 1 and
                evidence['owner_b_slots'] == 1 and
                0 <= evidence['shared_workers_active'] <=
                evidence['shared_worker_limit'] <= 64 and
                evidence['extra_work_admitted'] == 0)
    except (TypeError, ValueError, KeyError):
        return False
