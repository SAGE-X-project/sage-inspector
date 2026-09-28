"""Bind Registry lifecycle cases to the independent mutation sequence."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/registry-scenarios/registry-mutations.json'
OUTPUT = ROOT / 'vectors/0.10.0/reg03-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('REG-03-P', 'REG-03-N01', 'REG-03-N02', 'REG-03-N03',
       'REG-03-N04')


def main():
    raw = SOURCE.read_bytes()
    source = json.loads(raw)
    steps = source['steps']
    initial = steps[0]['input']['record']
    controller = initial['controller']

    def request(ordinal, state, version, *, prior=None):
        step = steps[ordinal]
        action = step['input']
        record = copy.deepcopy(initial)
        record.update(state=state, version=version)
        inp = {'record': record, 'operation': 'lifecycle-transition',
               'actor': controller if action['authorized'] else 'other-controller',
               'expected_version': action['expected_version'],
               'new_state': action['new_state']}
        if prior is not None:
            inp['prior_commit'] = {'step_id': steps[prior]['id'],
                                   'input': steps[prior]['input'],
                                   'expected': steps[prior]['expected']}
        return inp

    cases = [
        ('REG-03-P', 5, request(5, 'created', '1'),
         'ACCEPT', {'version': '2', 'state': 'active'}, 1,
         'controller activation commits exactly one version'),
        ('REG-03-N01', 3, request(3, 'created', '1'),
         'REJECT', {}, 0, 'stale expected version preserves created record'),
        ('REG-03-N02', 7, request(7, 'active', '2', prior=5),
         'REJECT', {}, 0,
         'second CAS with original version loses after committed activation'),
        ('REG-03-N03', 11, request(11, 'deactivated', '3', prior=9),
         'REJECT', {}, 0, 'terminal deactivation forbids reactivation'),
        ('REG-03-N04', 1, request(1, 'created', '1'),
         'REJECT', {}, 0, 'unauthorized actor cannot activate record'),
    ]
    maxed = copy.deepcopy(initial)
    maxed.update(state='active', version=str(2**64 - 1))
    controls = [
        {'name': 'version-ceiling', 'input': {'record': maxed,
          'operation': 'update-services', 'actor': controller,
          'expected_version': str(2**64 - 1),
          'services': maxed['services']}, 'expected': 'REJECT',
         'purpose': 'version must not wrap after uint64 maximum'},
        {'name': 'terminal-deactivate', 'input': request(9, 'active', '2'),
         'expected': 'ACCEPT',
         'purpose': 'authorized active-to-deactivated transition is terminal'},
    ]
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': hashlib.sha256(raw).hexdigest(),
        'scope': 'fixed public records and declarative CAS transitions; no registry writes or network access',
        'cases': [{'id': ident, 'source_step': steps[ordinal]['id'],
                   'input': inp,
                   'expected': {'verdict': verdict, 'output': output,
                                'effects': {'mutations': mutations}},
                   'purpose': purpose}
                  for ident, ordinal, inp, verdict, output, mutations, purpose
                  in cases],
        'supplemental': controls,
    }
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    for row in suite['cases']:
        ident = row['id']
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.registry.lifecycle.apply',
                             'input': row['input']},
                   'expected': row['expected']}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated', len(cases), 'REG-03 cases and', len(controls), 'controls')


if __name__ == '__main__':
    main()
