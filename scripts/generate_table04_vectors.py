"""Generate exact domain-separation byte fixtures for TABLE-04."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-04-P', 'TABLE-04-N01', 'TABLE-04-N02', 'TABLE-04-N03')
LABELS = {
    'registry_pop': ('sage-pop-0.10.0', ''),
    'registry_claim': ('sage-claim-0.10.0', '\0'),
    'card_proof': ('sage-card-0.10.0', '\0'),
    'guard_intent': ('sage-execution-intent|0.10.0', '\0'),
    'guard_result': ('sage-tool-result|0.10.0', '\0'),
    'wire_request': ('sage-wire-request|0.10.0', '\n'),
    'wire_response': ('sage-wire-response|0.10.0', '\n'),
    'hpke_combiner': ('sage-hpke-combiner|0.10.0', ''),
    'hpke_ack': ('sage-hpke-ack|0.10.0', ''),
    'hpke_info': ('sage-hpke-info|0.10.0', '\n'),
    'hpke_export': ('sage-hpke-export|0.10.0', '\n'),
    'hpke_complete': ('sage-hpke-complete|0.10.0', '\n'),
    'record_aad': ('sage-record|0.10.0', ''),
    'session_id': ('sage-session|0.10.0', ''),
    'session_c2s': ('sage-c2s-key|0.10.0', ''),
    'session_s2c': ('sage-s2c-key|0.10.0', ''),
    'original_capture': ('sage-original|0.10.0', '\0'),
    'policy_commitment': ('sage-policy|0.10.0', '\0'),
}


def main():
    valid = {'domains': {name: (label + delimiter).encode('ascii').hex()
                         for name, (label, delimiter) in LABELS.items()}}
    legacy = copy.deepcopy(valid)
    legacy['domains']['hpke_info'] = b'sage/hpke-info|v1\n'.hex()
    missing_lf = copy.deepcopy(valid)
    missing_lf['domains']['wire_request'] = b'sage-wire-request|0.10.0'.hex()
    wrong_hkdf = copy.deepcopy(valid)
    wrong_hkdf['domains']['hpke_combiner'] = valid['domains']['hpke_ack']
    rows = [
        ('TABLE-04-P', valid, 'ACCEPT', 'exact domain bytes in eighteen constructions'),
        ('TABLE-04-N01', legacy, 'REJECT', 'obsolete HPKE info label'),
        ('TABLE-04-N02', missing_lf, 'REJECT', 'omitted wire-request line feed'),
        ('TABLE-04-N03', wrong_hkdf, 'REJECT', 'acknowledgment domain used for combiner HKDF'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'matched_domains': len(LABELS)} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.domain.registry.check',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': {
            'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
            'spec/04-hpke.md': '1420818451ce8363a16e391647dbaca8ec2f06efa56b6507027a4e17f399fdd6',
            'spec/05-session.md': '8a45b8bdd3b6bfc399a94c420b2161b8f16db5c6b29ed2e85584a6282b17cce5',
            'spec/07-a2a.md': '5ded622fdaf67342d5c6b4327da0f5787bfe9df2dc58b233cdfb500ffc96b042',
            'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb',
            'spec/09-registry.md': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
            'profiles/agent-mcp-security.md': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f'},
        'scope': 'synthetic domain-byte dispatch; no signatures, HKDF derivation, deployed cryptographic interoperability, or release claim',
        'cases': cases}
    (ROOT / 'vectors/0.10.0/table04-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
