"""Revision-bound, host-facing contracts for cases without a local subject adapter.

These contracts check observation shape, rule identity, explicit source outcomes and
independent effect counts. They are partial inspection interfaces, never protocol
execution or implementation conformance evidence by themselves.
"""

import base64
import binascii
import json
import hashlib
import uuid

from current_spec_catalog import ROOT, require
from mcp_setup_model import initial as setup_initial, invariant as setup_invariant
from mcp_setup_model import step as setup_step


RULE_ASSERTIONS = {
    'MSET-01': ('authenticated_channel', 'session_owner_bound'),
    'MSET-02': ('outer_carriage_checked', 'replay_history_preserved'),
    'MSET-03': ('initialize_correlation_checked',),
    'MSET-04': ('notification_ack_checked',),
    'MSET-05': ('descriptor_and_gate_checked',),
    'MSET-06': ('monotonic_deadline_checked',),
    'MSET-07': ('fresh_owner_and_durable_state_checked',),
    'MSET-08': ('profile_scope_checked',),
    'MOWN-01': ('ownership_boundary_checked',),
    'MOWN-02': ('owner_publication_checked',),
    'MOWN-03': ('reservation_fence_checked',),
    'MOWN-04': ('closure_and_deadline_checked',),
    'MOWN-05': ('signature_role_checked',),
    'MOWN-06': ('mandatory_child_boundary_checked',),
}


SERVER_SETUP = ('initialize', 'send_ok', 'initialized', 'send_ok',
                'list', 'send_ok')
MSET06_SCENARIOS = {
    'mset-06-before-deadline': (SERVER_SETUP[:-1] +
                                ('tick_29999', 'send_ok'), 'READY'),
    'mset-06-deadline-equality': (SERVER_SETUP[:-1] +
                                 ('tick_30000', 'send_ok'), 'CLOSED'),
    'mset-06-slow-callback': (SERVER_SETUP[:-1] +
                              ('tick_30000', 'send_ok', 'call_2'), 'CLOSED'),
    'mset-06-uncertain-send': (SERVER_SETUP[:-1] +
                               ('send_fail', 'send_ok'), 'CLOSED'),
    'mset-06-deadline-after-callback': (SERVER_SETUP[:-1] +
                                        ('tick_30000', 'send_ok'), 'CLOSED'),
    'mset-06-close-completion-race': (SERVER_SETUP[:-1] +
                                      ('close', 'send_ok'), 'CLOSED'),
    'mset-06-ready-past-setup-deadline': (SERVER_SETUP +
                                          ('tick_30001',), 'READY'),
}
SETUP_MODEL_SCENARIOS = {
    **MSET06_SCENARIOS,
    'mset-02-output-barrier': (('initialize', 'call_2'), 'CLOSED'),
    'mset-02-send-failure-after-prepare':
        (('initialize', 'initialized', 'send_fail'), 'CLOSED'),
    'mset-02-setup-id-reuse': (SERVER_SETUP + ('call_0',), 'CLOSED'),
    'mset-02-history-exhaustion': (SERVER_SETUP + ('call_2',), 'CLOSED'),
    'mset-02-inner-rejection-replay':
        (('bad_inner', 'initialize'), 'CLOSED'),
    'mset-05-early-tool-call':
        (SERVER_SETUP[:2] + ('call_2',), 'CLOSED'),
    'mset-07-stale-ready': (SERVER_SETUP + ('close', 'call_2'), 'CLOSED'),
}
MSET03_SCENARIOS = {
    'mset-03-initialize-success': 'valid',
    'mset-03-unsupported-version': 'unsupported_version',
    'mset-03-capability-mismatch': 'capability_mismatch',
    'mset-03-wrong-request': 'wrong_request',
}
MSET04_SCENARIOS = {
    'mset-04-notification-ack': 'valid',
    'mset-04-ack-is-not-result': 'marker_not_guard_result',
    'mset-04-malformed-ack': 'malformed_ack',
    'mset-04-notification-has-id': 'notification_has_id',
    'mset-04-lost-ack': 'lost_ack',
}
MSET05_SCENARIOS = {
    'mset-05-discovery-success': 'valid',
    'mset-05-schema-replacement': 'schema_replacement',
    'mset-05-capability-not-authority': 'missing_endpoint',
    'mset-05-extended-descriptor': 'extended_descriptor',
}
MSET01_SCENARIOS = {
    'mset-01-valid-channel': 'valid',
    'mset-01-wrong-owner': 'wrong_owner',
    'mset-01-revoked-key': 'revoked_key',
}
MSET02_SCENARIOS = {
    'mset-02-exact-bytes': 'valid',
    'mset-02-size-boundary': 'oversized',
    'mset-02-json-duplicates': 'invalid_json',
    'mset-02-id-collision': 'id_collision',
}
MSET07_SCENARIOS = {
    'mset-07-fresh-reconnect': 'fresh_reconnect',
    'mset-07-terminal-preserved': 'terminal_preserved',
    'mset-07-missing-ledger': 'missing_ledger',
}
MSET08_SCENARIOS = {
    'mset-08-proposal-scope': 'unproven_conformance_claim',
    'mset-08-http-not-defined': 'http_excluded',
    'mset-08-historical-evidence': 'historical_not_promoted',
}
MERRATA_CONFIG_SCENARIOS = {
    'merrata-config-valid': 'valid_configuration',
    'merrata-config-reject': 'invalid_configuration',
    'merrata-config-change': 'closed_after_change',
}
SEMANTIC_MSET_IDS = (set(SETUP_MODEL_SCENARIOS) |
                     set(MSET01_SCENARIOS) | set(MSET02_SCENARIOS) |
                     set(MSET03_SCENARIOS) | set(MSET04_SCENARIOS) |
                     set(MSET05_SCENARIOS) | set(MSET07_SCENARIOS) |
                     set(MSET08_SCENARIOS) | set(MERRATA_CONFIG_SCENARIOS))
MCP_BINDING_ID = 'sage-mcp-non-http/0.10.0/mcp-2025-06-18'
MCP_DESCRIPTOR_DIGEST = 'sha256-jcs:f40nkKDT3hQs9poaxZxm8Bgw4hUV1f036fGMmIaKPtQ'


def merrata_config_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'descriptor_json', 'binding_id',
                              'peer_binding_id', 'sage_version',
                              'mcp_version', 'configured_digest',
                              'peer_digest', 'expected_peer_tuple_sha256',
                              'observed_peer_tuple_sha256',
                              'owner_descriptor_digest_at_construction',
                              'current_descriptor_digest', 'owner_state'} and
            type(evidence['descriptor_json']) is str and
            len(evidence['descriptor_json'].encode()) <= 16 * 1024 and
            all(evidence[key] is None or
                type(evidence[key]) is str and len(evidence[key]) <= 128
                for key in ('binding_id', 'peer_binding_id',
                            'sage_version', 'mcp_version',
                            'configured_digest', 'peer_digest')) and
            all(sha256_hex(evidence[key]) for key in
                ('expected_peer_tuple_sha256',
                 'observed_peer_tuple_sha256',
                 'owner_descriptor_digest_at_construction',
                 'current_descriptor_digest')) and
            evidence['owner_state'] in ('NEW', 'READY', 'CLOSED'),
            'bounded trusted local MCP configuration')
    if evidence['owner_descriptor_digest_at_construction'] != \
            evidence['current_descriptor_digest']:
        return ('closed_after_change' if evidence['owner_state'] == 'CLOSED'
                else 'unsafe_configuration_change')
    try:
        descriptor = json.loads(evidence['descriptor_json'],
                                object_pairs_hook=unique_json_object)
    except (ValueError, TypeError):
        return 'invalid_configuration'
    digest_hex = canonical_tool_digest(pinned_tool())
    digest = 'sha256-jcs:' + base64.urlsafe_b64encode(
        bytes.fromhex(digest_hex)).rstrip(b'=').decode()
    if digest != MCP_DESCRIPTOR_DIGEST or descriptor != pinned_tool() or \
            canonical_tool_digest(descriptor) != digest_hex or \
            evidence['binding_id'] != MCP_BINDING_ID or \
            evidence['peer_binding_id'] != MCP_BINDING_ID or \
            evidence['sage_version'] != '0.10.0' or \
            evidence['mcp_version'] != '2025-06-18' or \
            evidence['configured_digest'] != MCP_DESCRIPTOR_DIGEST or \
            evidence['peer_digest'] != MCP_DESCRIPTOR_DIGEST or \
            evidence['expected_peer_tuple_sha256'] != \
            evidence['observed_peer_tuple_sha256']:
        return 'invalid_configuration'
    return 'valid_configuration'


def merrata_config_sample(ident):
    digest = canonical_tool_digest(pinned_tool())
    evidence = {'descriptor_json': json.dumps(pinned_tool(),
                                               sort_keys=True,
                                               separators=(',', ':')),
                'binding_id': MCP_BINDING_ID,
                'peer_binding_id': MCP_BINDING_ID,
                'sage_version': '0.10.0', 'mcp_version': '2025-06-18',
                'configured_digest': MCP_DESCRIPTOR_DIGEST,
                'peer_digest': MCP_DESCRIPTOR_DIGEST,
                'expected_peer_tuple_sha256': 'a' * 64,
                'observed_peer_tuple_sha256': 'a' * 64,
                'owner_descriptor_digest_at_construction': digest,
                'current_descriptor_digest': digest,
                'owner_state': 'NEW'}
    if ident == 'merrata-config-reject':
        evidence['binding_id'] = None
    elif ident == 'merrata-config-change':
        evidence['owner_descriptor_digest_at_construction'] = 'b' * 64
        evidence['owner_state'] = 'CLOSED'
    return evidence


def mset08_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'design_adopted', 'claim', 'transport',
                              'runtime_evidence_ids', 'http_profile_defined',
                              'fallback_effect_ids',
                              'historical_not_run_count',
                              'historical_promoted_ids'} and
            type(evidence['design_adopted']) is bool and
            evidence['claim'] in ('runtime_conformance',
                                  'historical_pass', 'no_claim') and
            evidence['transport'] in ('non_http', 'http') and
            bounded_ids(evidence['runtime_evidence_ids']) and
            type(evidence['http_profile_defined']) is bool and
            bounded_ids(evidence['fallback_effect_ids']) and
            type(evidence['historical_not_run_count']) is int and
            0 <= evidence['historical_not_run_count'] <= 10000 and
            bounded_ids(evidence['historical_promoted_ids']),
            'bounded design-adoption and excluded transport claims')
    if evidence['claim'] == 'runtime_conformance' and \
            evidence['design_adopted'] and \
            not evidence['runtime_evidence_ids']:
        return 'unproven_conformance_claim'
    if evidence['transport'] == 'http' and \
            not evidence['http_profile_defined'] and \
            not evidence['fallback_effect_ids']:
        return 'http_excluded'
    if evidence['claim'] == 'historical_pass' and \
            evidence['historical_not_run_count'] == 71 and \
            not evidence['historical_promoted_ids']:
        return 'historical_not_promoted'
    return 'unjustified_scope_or_promotion'


def mset08_sample(ident):
    evidence = {'design_adopted': True, 'claim': 'no_claim',
                'transport': 'non_http', 'runtime_evidence_ids': [],
                'http_profile_defined': False, 'fallback_effect_ids': [],
                'historical_not_run_count': 71,
                'historical_promoted_ids': []}
    if ident == 'mset-08-proposal-scope':
        evidence['claim'] = 'runtime_conformance'
    elif ident == 'mset-08-http-not-defined':
        evidence['transport'] = 'http'
    elif ident == 'mset-08-historical-evidence':
        evidence['claim'] = 'historical_pass'
    return evidence


def mset07_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'old_session_id', 'new_session_id',
                              'authenticated_session_ids',
                              'completed_setup_session_ids',
                              'old_call_id', 'old_dispatch_count',
                              'new_dispatch_count',
                              'terminal_digest_before',
                              'terminal_digest_after',
                              'client_consumed_before',
                              'client_consumed_after',
                              'ledger_present_before',
                              'ledger_present_after',
                              'empty_ledger_created'} and
            all(type(evidence[key]) is str and 1 <= len(evidence[key]) <= 128
                for key in ('old_session_id', 'new_session_id',
                            'old_call_id')) and
            all(bounded_ids(evidence[key]) for key in
                ('authenticated_session_ids',
                 'completed_setup_session_ids')) and
            all(type(evidence[key]) is int and
                0 <= evidence[key] <= 1
                for key in ('old_dispatch_count', 'new_dispatch_count')) and
            all(evidence[key] is None or sha256_hex(evidence[key])
                for key in ('terminal_digest_before',
                            'terminal_digest_after')) and
            all(type(evidence[key]) is bool for key in
                ('client_consumed_before', 'client_consumed_after',
                 'ledger_present_before', 'ledger_present_after',
                 'empty_ledger_created')),
            'bounded reconnect and durable ledger observations')
    if not evidence['ledger_present_before']:
        return ('missing_ledger' if not evidence['ledger_present_after'] and
                not evidence['empty_ledger_created'] and
                evidence['new_dispatch_count'] == 0 else
                'ledger_recreated_or_dispatched')
    if evidence['new_session_id'] == evidence['old_session_id'] or \
            evidence['new_session_id'] not in \
            evidence['authenticated_session_ids'] or \
            evidence['new_session_id'] not in \
            evidence['completed_setup_session_ids'] or \
            not evidence['ledger_present_after'] or \
            evidence['empty_ledger_created'] or \
            evidence['new_dispatch_count'] != 0:
        return 'invalid_reconnect'
    if evidence['terminal_digest_before'] is not None:
        return ('terminal_preserved'
                if evidence['terminal_digest_before'] ==
                evidence['terminal_digest_after'] and
                evidence['client_consumed_before'] and
                evidence['client_consumed_after'] and
                evidence['old_dispatch_count'] == 1 else
                'terminal_changed')
    return ('fresh_reconnect' if evidence['terminal_digest_after'] is None and
            evidence['old_dispatch_count'] == 1 else
            'old_call_reexecuted')


def mset07_sample(ident):
    evidence = {'old_session_id': 'session-1',
                'new_session_id': 'session-2',
                'authenticated_session_ids': ['session-2'],
                'completed_setup_session_ids': ['session-2'],
                'old_call_id': 'call-1', 'old_dispatch_count': 1,
                'new_dispatch_count': 0,
                'terminal_digest_before': None,
                'terminal_digest_after': None,
                'client_consumed_before': False,
                'client_consumed_after': False,
                'ledger_present_before': True,
                'ledger_present_after': True,
                'empty_ledger_created': False}
    if ident == 'mset-07-terminal-preserved':
        evidence['terminal_digest_before'] = 'a' * 64
        evidence['terminal_digest_after'] = 'a' * 64
        evidence['client_consumed_before'] = True
        evidence['client_consumed_after'] = True
    elif ident == 'mset-07-missing-ledger':
        evidence['ledger_present_before'] = False
        evidence['ledger_present_after'] = False
        evidence['old_dispatch_count'] = 0
    return evidence


def mset02_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'outer_request_id', 'sent_plaintext_b64',
                              'received_plaintext_b64', 'record_bytes',
                              'wire_bytes'} and
            canonical_uuid4(evidence['outer_request_id']) and
            all(type(evidence[key]) is str and len(evidence[key]) <= 32 * 1024
                for key in ('sent_plaintext_b64', 'received_plaintext_b64')) and
            all(type(evidence[key]) is int and
                0 <= evidence[key] <= 128 * 1024
                for key in ('record_bytes', 'wire_bytes')),
            'bounded MCP carriage observations')
    try:
        sent = base64.b64decode(evidence['sent_plaintext_b64'], validate=True)
        received = base64.b64decode(evidence['received_plaintext_b64'],
                                    validate=True)
    except (ValueError, binascii.Error):
        return 'invalid_encoding'
    require(evidence['record_bytes'] >= len(received) and
            evidence['wire_bytes'] >= evidence['record_bytes'],
            'record and wire size relationship')
    if len(sent) > 16348 or len(received) > 16348 or \
            evidence['record_bytes'] > 16384 or \
            evidence['wire_bytes'] > 32768:
        return 'oversized'
    try:
        message = json.loads(received.decode('utf-8'),
                             object_pairs_hook=unique_json_object)
    except (UnicodeError, ValueError, TypeError):
        return 'invalid_json'
    if type(message) is not dict or \
            not {'jsonrpc', 'id', 'method'} <= set(message) or \
            message['jsonrpc'] != '2.0' or \
            not canonical_uuid4(message['id']) or \
            type(message['method']) is not str:
        return 'invalid_json'
    if evidence['outer_request_id'] == message['id']:
        return 'id_collision'
    if sent != received:
        return 'bytes_changed'
    return 'valid'


def mset02_sample(ident):
    inner = '123e4567-e89b-42d3-a456-426614174001'
    outer = '123e4567-e89b-42d3-a456-426614174000'
    message = {'jsonrpc': '2.0', 'id': inner, 'method': 'initialize',
               'params': {'protocolVersion': '2025-06-18',
                          'capabilities': {},
                          'clientInfo': {'name': 'local-fixture', 'version': '1'}}}
    raw = json.dumps(message, separators=(',', ':')).encode()
    if ident == 'mset-02-size-boundary':
        raw = b'x' * 16349
    elif ident == 'mset-02-json-duplicates':
        raw = b'{"jsonrpc":"2.0","jsonrpc":"2.0"}'
    elif ident == 'mset-02-id-collision':
        outer = inner
    encoded = base64.b64encode(raw).decode()
    record_bytes = len(raw) + 32
    return {'outer_request_id': outer, 'sent_plaintext_b64': encoded,
            'received_plaintext_b64': encoded, 'record_bytes': record_bytes,
            'wire_bytes': record_bytes + 64}


def mset01_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'session_id', 'owner_session_id',
                              'readiness_session_id', 'peer_id',
                              'owner_peer_id', 'key_tuple_sha256',
                              'owner_key_tuple_sha256', 'key_id',
                              'authenticated_handshake_ids',
                              'validated_record_ids',
                              'active_registry_key_ids'} and
            all(type(evidence[key]) is str and 1 <= len(evidence[key]) <= 128
                for key in ('session_id', 'owner_session_id',
                            'readiness_session_id', 'peer_id',
                            'owner_peer_id', 'key_id')) and
            sha256_hex(evidence['key_tuple_sha256']) and
            sha256_hex(evidence['owner_key_tuple_sha256']) and
            all(bounded_ids(evidence[key]) for key in
                ('authenticated_handshake_ids', 'validated_record_ids',
                 'active_registry_key_ids')),
            'bounded channel ownership and registry observations')
    if evidence['session_id'] != evidence['owner_session_id'] or \
            evidence['session_id'] != evidence['readiness_session_id'] or \
            evidence['peer_id'] != evidence['owner_peer_id'] or \
            evidence['key_tuple_sha256'] != evidence['owner_key_tuple_sha256']:
        return 'wrong_owner'
    if evidence['key_id'] not in evidence['active_registry_key_ids']:
        return 'revoked_key'
    if evidence['session_id'] not in evidence['authenticated_handshake_ids'] or \
            evidence['session_id'] not in evidence['validated_record_ids']:
        return 'unauthenticated_channel'
    return 'valid'


def mset01_sample(ident):
    evidence = {'session_id': 'session-1', 'owner_session_id': 'session-1',
                'readiness_session_id': 'session-1',
                'peer_id': 'did:sage:peer-1', 'owner_peer_id': 'did:sage:peer-1',
                'key_tuple_sha256': 'a' * 64,
                'owner_key_tuple_sha256': 'a' * 64,
                'key_id': 'key-1',
                'authenticated_handshake_ids': ['session-1'],
                'validated_record_ids': ['session-1'],
                'active_registry_key_ids': ['key-1']}
    if ident == 'mset-01-wrong-owner':
        evidence['readiness_session_id'] = 'session-2'
    elif ident == 'mset-01-revoked-key':
        evidence['active_registry_key_ids'] = []
    return evidence
PINNED_TOOL_SHA256 = 'c3edd622a7c90baa028118f63af42a91f354fe7202070ef91a4bd349e4048204'


def pinned_tool():
    raw = (ROOT / 'verification/0.10.0/mcp-consolidated-proposal/tool.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == PINNED_TOOL_SHA256,
            'pinned MCP tool descriptor')
    return json.loads(raw)


def canonical_tool_digest(tool):
    return hashlib.sha256(json.dumps(tool, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def mset05_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'request_id', 'response_json', 'outer_success',
                              'outer_error', 'configured_digest',
                              'endpoint_install_ids'} and
            canonical_uuid4(evidence['request_id']) and
            type(evidence['response_json']) is str and
            len(evidence['response_json'].encode()) <= 16 * 1024 and
            type(evidence['outer_success']) is bool and
            (evidence['outer_error'] is None or
             type(evidence['outer_error']) is str and
             len(evidence['outer_error']) <= 128) and
            sha256_hex(evidence['configured_digest']) and
            bounded_ids(evidence['endpoint_install_ids']),
            'bounded authenticated discovery response')
    try:
        response = json.loads(evidence['response_json'],
                              object_pairs_hook=unique_json_object)
    except (ValueError, TypeError):
        return 'malformed_listing'
    if type(response) is not dict or \
            set(response) != {'jsonrpc', 'id', 'result'} or \
            response['jsonrpc'] != '2.0' or \
            response['id'] != evidence['request_id'] or \
            type(response['result']) is not dict or \
            set(response['result']) != {'tools'} or \
            type(response['result']['tools']) is not list or \
            len(response['result']['tools']) != 1 or \
            not evidence['outer_success'] or evidence['outer_error'] is not None:
        return 'malformed_listing'
    discovered = response['result']['tools'][0]
    expected = pinned_tool()
    if type(discovered) is not dict:
        return 'malformed_listing'
    if set(discovered) - set(expected):
        return 'extended_descriptor'
    if discovered != expected or \
            evidence['configured_digest'] != canonical_tool_digest(expected) or \
            canonical_tool_digest(discovered) != evidence['configured_digest']:
        return 'schema_replacement'
    if not evidence['endpoint_install_ids']:
        return 'missing_endpoint'
    return 'valid'


def mset05_sample(ident):
    tool = pinned_tool()
    evidence = {'request_id': '123e4567-e89b-42d3-a456-426614174003',
                'outer_success': True, 'outer_error': None,
                'configured_digest': canonical_tool_digest(tool),
                'endpoint_install_ids': ['endpoint-1']}
    if ident == 'mset-05-schema-replacement':
        tool = dict(tool, name='replacement_tool')
    elif ident == 'mset-05-extended-descriptor':
        tool = dict(tool, title='unexpected metadata')
    elif ident == 'mset-05-capability-not-authority':
        evidence['endpoint_install_ids'] = []
    evidence['response_json'] = json.dumps(
        {'jsonrpc': '2.0', 'id': evidence['request_id'],
         'result': {'tools': [tool]}}, separators=(',', ':'))
    return evidence


def bounded_ids(value):
    return type(value) is list and len(value) <= 64 and \
        all(type(item) is str and 1 <= len(item) <= 128 for item in value) and \
        len(value) == len(set(value))


def sha256_hex(value):
    return type(value) is str and len(value) == 64 and \
        all(char in '0123456789abcdef' for char in value)


def mset04_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'notification_json', 'request_hash',
                              'ack_request_hash', 'ack_plaintext',
                              'outer_success', 'outer_error',
                              'guard_consume_attempt_ids', 'guard_output_ids',
                              'deadline_elapsed_ms'} and
            type(evidence['notification_json']) is str and
            len(evidence['notification_json'].encode()) <= 4096 and
            sha256_hex(evidence['request_hash']) and
            (evidence['ack_request_hash'] is None or
             sha256_hex(evidence['ack_request_hash'])) and
            (evidence['ack_plaintext'] is None or
             type(evidence['ack_plaintext']) is str and
             len(evidence['ack_plaintext'].encode()) <= 4096) and
            type(evidence['outer_success']) is bool and
            (evidence['outer_error'] is None or
             type(evidence['outer_error']) is str and
             len(evidence['outer_error']) <= 128) and
            bounded_ids(evidence['guard_consume_attempt_ids']) and
            bounded_ids(evidence['guard_output_ids']) and
            type(evidence['deadline_elapsed_ms']) is int and
            0 <= evidence['deadline_elapsed_ms'] < 2**64,
            'bounded initialized notification and acknowledgement')
    try:
        notification = json.loads(evidence['notification_json'],
                                  object_pairs_hook=unique_json_object)
    except (ValueError, TypeError):
        return 'malformed_notification'
    if type(notification) is not dict:
        return 'malformed_notification'
    if 'id' in notification:
        return 'notification_has_id'
    if notification != {'jsonrpc': '2.0',
                        'method': 'notifications/initialized'}:
        return 'malformed_notification'
    if evidence['ack_plaintext'] is None and \
            evidence['deadline_elapsed_ms'] >= 30000:
        return 'lost_ack'
    if evidence['ack_plaintext'] != '{}' or \
            evidence['ack_request_hash'] != evidence['request_hash'] or \
            not evidence['outer_success'] or evidence['outer_error'] is not None:
        return 'malformed_ack'
    if evidence['guard_consume_attempt_ids'] and \
            not evidence['guard_output_ids']:
        return 'marker_not_guard_result'
    if evidence['guard_output_ids']:
        return 'unexpected_guard_output'
    return 'valid'


def mset04_sample(ident):
    evidence = {'notification_json':
                '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                'request_hash': 'a' * 64, 'ack_request_hash': 'a' * 64,
                'ack_plaintext': '{}', 'outer_success': True,
                'outer_error': None, 'guard_consume_attempt_ids': [],
                'guard_output_ids': [], 'deadline_elapsed_ms': 1000}
    if ident == 'mset-04-ack-is-not-result':
        evidence['guard_consume_attempt_ids'] = ['consume-1']
    elif ident == 'mset-04-malformed-ack':
        evidence['ack_plaintext'] = '{ }'
    elif ident == 'mset-04-notification-has-id':
        evidence['notification_json'] = (
            '{"jsonrpc":"2.0","method":"notifications/initialized","id":1}')
    elif ident == 'mset-04-lost-ack':
        evidence['ack_plaintext'] = None
        evidence['ack_request_hash'] = None
        evidence['outer_success'] = False
        evidence['deadline_elapsed_ms'] = 30000
    return evidence


def canonical_uuid4(value):
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON member')
        value[key] = item
    return value


def mset03_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'outer_request_id', 'inner_request_id',
                              'response_outer_id', 'response_json',
                              'outer_success', 'outer_error'} and
            all(canonical_uuid4(evidence[key]) for key in
                ('outer_request_id', 'inner_request_id',
                 'response_outer_id')) and
            evidence['outer_request_id'] != evidence['inner_request_id'] and
            type(evidence['response_json']) is str and
            len(evidence['response_json'].encode()) <= 16 * 1024 and
            type(evidence['outer_success']) is bool and
            (evidence['outer_error'] is None or
             type(evidence['outer_error']) is str and
             len(evidence['outer_error']) <= 128),
            'bounded authenticated initialize response')
    try:
        inner = json.loads(evidence['response_json'],
                           object_pairs_hook=unique_json_object)
    except (ValueError, TypeError):
        return 'malformed_response'
    if type(inner) is not dict or set(inner) != {'jsonrpc', 'id', 'result'} or \
            inner['jsonrpc'] != '2.0' or type(inner['result']) is not dict:
        return 'malformed_response'
    if evidence['response_outer_id'] != evidence['outer_request_id'] or \
            inner['id'] != evidence['inner_request_id']:
        return 'wrong_request'
    if not evidence['outer_success'] or evidence['outer_error'] is not None:
        return 'outer_failure'
    result = inner['result']
    if set(result) != {'protocolVersion', 'serverInfo', 'capabilities'} or \
            type(result['serverInfo']) is not dict or \
            set(result['serverInfo']) != {'name', 'version'} or \
            not all(type(value) is str and 1 <= len(value) <= 128
                    for value in result['serverInfo'].values()):
        return 'malformed_response'
    if result['protocolVersion'] != '2025-06-18':
        return 'unsupported_version'
    if result['capabilities'] != {'tools': {}}:
        return 'capability_mismatch'
    return 'valid'


def mset03_sample(ident):
    outer = '123e4567-e89b-42d3-a456-426614174000'
    inner = '123e4567-e89b-42d3-a456-426614174001'
    response = {'jsonrpc': '2.0', 'id': inner,
                'result': {'protocolVersion': '2025-06-18',
                           'serverInfo': {'name': 'local-fixture', 'version': '1'},
                           'capabilities': {'tools': {}}}}
    evidence = {'outer_request_id': outer, 'inner_request_id': inner,
                'response_outer_id': outer, 'outer_success': True,
                'outer_error': None}
    if ident == 'mset-03-unsupported-version':
        response['result']['protocolVersion'] = '2024-11-05'
    elif ident == 'mset-03-capability-mismatch':
        response['result']['capabilities'] = {'resources': {}}
    elif ident == 'mset-03-wrong-request':
        response['id'] = '123e4567-e89b-42d3-a456-426614174002'
    evidence['response_json'] = json.dumps(response, separators=(',', ':'))
    return evidence


def setup_model_check(ident, events):
    prescribed, phase = SETUP_MODEL_SCENARIOS[ident]
    if type(events) is not list or events != list(prescribed):
        return False
    state = setup_initial('server')
    try:
        for event in events:
            after = setup_step(state, event,
                               2 if ident == 'mset-02-history-exhaustion' else 3)
            setup_invariant(state, event, after)
            state = after
    except (ValueError, AssertionError):
        return False
    return (state.phase == phase and not state.admitted and
            (ident != 'mset-02-inner-rejection-replay' or state.replay != 0))


def assertions_for(rule_id):
    return RULE_ASSERTIONS.get(rule_id, ('normative_boundary_checked',))


def expected_outcome(case):
    return case['expected']


def case_input(case, rule, track, phase):
    trigger = case.get('input', case.get('scenario'))
    return {'operation': 'sage.spec.host_case',
            'phase': phase, 'id': case['id'], 'track': track,
            'rule_id': rule['id'], 'source': rule['source'],
            'source_line': rule['line'], 'trigger': trigger,
            'preconditions': case.get('preconditions', case.get('planned_method'))}


def expected_result(ident=None):
    if ident == 'REG-08-N04':
        return {'verdict': 'REJECT',
                'output': {'matched': False, 'reason': 'spec_underspecified'},
                'effects': {}}
    return {'verdict': 'ACCEPT',
            'output': {'matched': True, 'reason': 'case_contract'}, 'effects': {}}


def sample_observation(case, rule, track):
    ident = case['id']
    assertions = {name: True for name in assertions_for(rule['id'])
                  if not (ident in MSET01_SCENARIOS and
                          name in ('authenticated_channel',
                                   'session_owner_bound'))
                  if not (ident in MSET06_SCENARIOS and
                          name == 'monotonic_deadline_checked') and
                  not (ident in MSET03_SCENARIOS and
                       name == 'initialize_correlation_checked') and
                  not (ident in MSET04_SCENARIOS and
                       name == 'notification_ack_checked') and
                  not (ident in MSET05_SCENARIOS and
                       name == 'descriptor_and_gate_checked') and
                  not (ident in MSET07_SCENARIOS and
                       name == 'fresh_owner_and_durable_state_checked') and
                  not (ident in MSET08_SCENARIOS and
                       name == 'profile_scope_checked')}
    result = {'case_id': ident, 'track': track,
              'observed_outcome': case['expected'], 'assertions': assertions,
              'observer_effects': 0, 'subject_effects': 0}
    if ident in SETUP_MODEL_SCENARIOS:
        result['model_events'] = list(SETUP_MODEL_SCENARIOS[ident][0])
    if ident in MSET03_SCENARIOS:
        result['mcp_response'] = mset03_sample(ident)
    if ident in MSET04_SCENARIOS:
        result['ack_evidence'] = mset04_sample(ident)
    if ident in MSET05_SCENARIOS:
        result['discovery_evidence'] = mset05_sample(ident)
    if ident in MSET01_SCENARIOS:
        result['channel_evidence'] = mset01_sample(ident)
    if ident in MSET02_SCENARIOS:
        result['carriage_evidence'] = mset02_sample(ident)
    if ident in MSET07_SCENARIOS:
        result['reconnect_evidence'] = mset07_sample(ident)
    if ident in MSET08_SCENARIOS:
        result['scope_evidence'] = mset08_sample(ident)
    if ident in MERRATA_CONFIG_SCENARIOS:
        result['configuration_evidence'] = merrata_config_sample(ident)
    return result


def inspect(case, rule, track, phase, observed):
    if case['id'] == 'REG-08-N04':
        return expected_result(case['id'])
    fields = {'case_id', 'track', 'observed_outcome', 'assertions',
              'observer_effects', 'subject_effects'}
    if case['id'] in SETUP_MODEL_SCENARIOS:
        fields.add('model_events')
    if case['id'] in MSET03_SCENARIOS:
        fields.add('mcp_response')
    if case['id'] in MSET04_SCENARIOS:
        fields.add('ack_evidence')
    if case['id'] in MSET05_SCENARIOS:
        fields.add('discovery_evidence')
    if case['id'] in MSET01_SCENARIOS:
        fields.add('channel_evidence')
    if case['id'] in MSET02_SCENARIOS:
        fields.add('carriage_evidence')
    if case['id'] in MSET07_SCENARIOS:
        fields.add('reconnect_evidence')
    if case['id'] in MSET08_SCENARIOS:
        fields.add('scope_evidence')
    if case['id'] in MERRATA_CONFIG_SCENARIOS:
        fields.add('configuration_evidence')
    require(type(observed) is dict and
            set(observed) == fields and
            observed['case_id'] == case['id'] and observed['track'] == track and
            type(observed['observed_outcome']) is str and
            type(observed['assertions']) is dict and
            type(observed['observer_effects']) is int and
            type(observed['subject_effects']) is int and
            observed['observer_effects'] >= 0 and observed['subject_effects'] >= 0,
            'host observation shape and identity')
    required = tuple(name for name in assertions_for(rule['id'])
                     if not (case['id'] in MSET01_SCENARIOS and
                             name in ('authenticated_channel',
                                      'session_owner_bound'))
                     if not (case['id'] in MSET06_SCENARIOS and
                             name == 'monotonic_deadline_checked') and
                     not (case['id'] in MSET03_SCENARIOS and
                          name == 'initialize_correlation_checked') and
                     not (case['id'] in MSET04_SCENARIOS and
                          name == 'notification_ack_checked') and
                     not (case['id'] in MSET05_SCENARIOS and
                          name == 'descriptor_and_gate_checked') and
                     not (case['id'] in MSET07_SCENARIOS and
                          name == 'fresh_owner_and_durable_state_checked') and
                     not (case['id'] in MSET08_SCENARIOS and
                          name == 'profile_scope_checked'))
    assertions_valid = (set(observed['assertions']) == set(required) and
                        all(observed['assertions'][key] is True for key in required))
    effects_agree = observed['observer_effects'] == observed['subject_effects']
    # Setup cannot dispatch any protected call. Other cases retain an explicit
    # independent counter agreement without guessing a normative effect count.
    setup_effects = phase != 4 or observed['observer_effects'] == 0
    model_ok = (case['id'] not in SETUP_MODEL_SCENARIOS or
                setup_model_check(case['id'], observed['model_events']))
    mcp_response_ok = (case['id'] not in MSET03_SCENARIOS or
                       mset03_classification(observed['mcp_response']) ==
                       MSET03_SCENARIOS[case['id']])
    ack_ok = (case['id'] not in MSET04_SCENARIOS or
              mset04_classification(observed['ack_evidence']) ==
              MSET04_SCENARIOS[case['id']])
    discovery_ok = (case['id'] not in MSET05_SCENARIOS or
                    mset05_classification(observed['discovery_evidence']) ==
                    MSET05_SCENARIOS[case['id']])
    channel_ok = (case['id'] not in MSET01_SCENARIOS or
                  mset01_classification(observed['channel_evidence']) ==
                  MSET01_SCENARIOS[case['id']])
    carriage_ok = (case['id'] not in MSET02_SCENARIOS or
                   mset02_classification(observed['carriage_evidence']) ==
                   MSET02_SCENARIOS[case['id']])
    reconnect_ok = (case['id'] not in MSET07_SCENARIOS or
                    mset07_classification(observed['reconnect_evidence']) ==
                    MSET07_SCENARIOS[case['id']])
    scope_ok = (case['id'] not in MSET08_SCENARIOS or
                mset08_classification(observed['scope_evidence']) ==
                MSET08_SCENARIOS[case['id']])
    configuration_ok = (case['id'] not in MERRATA_CONFIG_SCENARIOS or
                        merrata_config_classification(
                            observed['configuration_evidence']) ==
                        MERRATA_CONFIG_SCENARIOS[case['id']])
    matched = (observed['observed_outcome'] == expected_outcome(case) and
               assertions_valid and effects_agree and setup_effects and
               model_ok and mcp_response_ok and ack_ok and discovery_ok and
               channel_ok and carriage_ok and reconnect_ok and scope_ok and
               configuration_ok)
    return {'verdict': 'ACCEPT' if matched else 'REJECT',
            'output': {'matched': matched,
                       'reason': 'case_contract' if matched else
                                 'outcome_assertion_or_effect_mismatch'},
            'effects': {}}
