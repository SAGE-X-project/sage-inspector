"""Independent, public signed fixtures for the bounded multi-hop core seam."""

import copy
import hashlib
import json
from pathlib import Path

import generate_guard_vectors as guard


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('mrevision-hop-authorized', 'mrevision-hop-unapproved',
       'mrevision-parent-no-grant')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    v = json.loads((ROOT / 'vectors/0.10.0/guard-client.json').read_text())
    parent = copy.deepcopy(v['input'])
    incoming = bytes.fromhex(parent['envelope_hex'])
    upstream = json.loads(incoming)['intent']
    issuer = upstream['recipient']
    recipient = upstream['issuer']
    child = copy.deepcopy(upstream)
    child.update(issuer=issuer, recipient=recipient, keyid=issuer + '#signing-1',
                 request_id=guard.uuid(11), call_id=guard.uuid(12),
                 parent_call_id=upstream['call_id'],
                 nonce=guard.b64(bytes([2] * 16)),
                 original_digest=sha(guard.capture([incoming])))
    policy = copy.deepcopy(parent['approved_policy'])
    policy['issuer'] = issuer
    child['policy_digest'] = guard.policy_digest(policy)
    outgoing = guard.jcs(guard.sign('intent', child))
    base = copy.deepcopy(parent)
    base.update(expected_issuer=issuer, expected_recipient=recipient,
                original_digest=child['original_digest'],
                approved_policy=policy,
                public_key_hex=guard.pub(guard.SK))
    common = {'incoming_hex': incoming.hex(), 'outgoing_hex': outgoing.hex(),
              'parent': parent, 'begin': True}
    allowed = dict(common, child=base, parent_allowed=True)
    no_policy = dict(common, child=dict(base, policy_allow=False),
                     parent_allowed=True)
    no_parent = dict(common, child=base, parent_allowed=False)
    return (
        (IDS[0], allowed, {'opened': True, 'began': True, 'journal': True,
                           'handoffs': 1, 'parent_checks': 3}),
        (IDS[1], no_policy, {'opened': False, 'began': False, 'journal': False,
                             'handoffs': 0, 'parent_checks': 1}),
        (IDS[2], no_parent, {'opened': False, 'began': False, 'journal': False,
                             'handoffs': 0, 'parent_checks': 1}),
    )


def main():
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'source_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-client.json').read_bytes()),
             'scope': 'local Go/Rust hop core seam only; host routing, persistent parent admission, and UNKNOWN provenance require separate observation',
             'cases': []}
    for ident, inp, output in cases():
        payload = {'operation': 'sage.guard.hop.open', 'input': inp}
        expected = {'verdict': 'ACCEPT' if output['opened'] else 'REJECT',
                    'output': output, 'effects': {'handoff': output['handoffs']}}
        suite['cases'].append({'id': ident, 'input': payload,
                               'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime', 'input': payload,
                   'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative, 'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-hop.json').write_text(json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
