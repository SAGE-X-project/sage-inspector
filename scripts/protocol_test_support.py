"""Test-local protocol cases; scripted observations are not real core evidence."""
import copy
import json
from inspect_session import ROOT

SELECTION = {
    'hpke-schedule': ('schedule-0','completion-valid','wrong-ack','different-pending-request','unsigned-completion','unknown-transcript-member'),
    'session-records': ('c2s-open-0','transcript'),
    'http-signatures': ('base-sage-response','base-missing-request','archive-response-wrong-request-signature'),
    'http-boundaries': ('valid-response','wrong-request-hash','missing-stored-request','stale-hash-with-valid-outer-binding'),
}


def selected_suite(name):
    suite=json.loads((ROOT/'vectors/0.10.0'/(name+'.json')).read_text())
    suite['cases']=[c for c in suite['cases'] if c['id'] in SELECTION[name]]
    suite['id']='unit-'+name
    return suite


def websocket_suite():
    # The wrapper declares controlled observations, not a public core API binding.
    http=json.loads((ROOT/'vectors/0.10.0/http-boundaries.json').read_text())
    request=next(c for c in http['cases'] if c['id']=='valid-request')['input']
    envelope=bytes.fromhex(request['request_hex']).split(b'\r\n\r\n',1)[1]
    base=dict(tls_authenticated=True, message_kind='text', compressed=False,
              fragments_hex=[envelope.hex()], expected_recipient=request['expected_recipient'],
              envelope_signature_verified=True, recipient_matches=True, request_binding_matches=True)
    controls=[('valid-message',{},'ACCEPT'),
              ('fragmented-message',dict(fragments_hex=[envelope[:7].hex(),envelope[7:].hex()]),'ACCEPT'),
              ('binary-message',dict(message_kind='binary'),'REJECT'),
              ('compressed-message',dict(compressed=True),'REJECT'),
              ('untrusted-connection',dict(tls_authenticated=False),'REJECT'),
              ('unverified-envelope',dict(envelope_signature_verified=False),'REJECT'),
              ('wrong-recipient',dict(recipient_matches=False),'REJECT'),
              ('wrong-request-binding',dict(request_binding_matches=False),'REJECT')]
    return dict(schema_version=1, protocol_version='0.10.0', profile='primitive-foundation',id='unit-ws-binding',
                sources=[dict(id='transport',kind='spec-derived',uri='sage-spec/spec/08-transport.md',reference='TRANSPORT-06; test-only trusted seam declarations, no socket or real verification')],
                cases=[dict(id=name,operation='test.ws.binding-observation',input=dict(copy.deepcopy(base),**changes),
                            expected=dict(verdict=verdict,output={}),derivation='Test-only boundary expectation; no socket or cryptographic execution.',rule_ids=['TRANSPORT-06'],source_ids=['transport'])
                       for name,changes,verdict in controls])
