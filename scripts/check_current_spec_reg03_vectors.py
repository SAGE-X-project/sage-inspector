"""Audit Registry compare-and-swap fixtures with an independent state model."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from check_current_spec_reg01_vectors import decoded
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg03-scenarios.json'
ORIGINAL = 'vectors/0.10.0/registry-scenarios/registry-mutations.json'
IDS = ('REG-03-P', 'REG-03-N01', 'REG-03-N02', 'REG-03-N03',
       'REG-03-N04')
STEPS = {'REG-03-P': 5, 'REG-03-N01': 3, 'REG-03-N02': 7,
         'REG-03-N03': 11, 'REG-03-N04': 1}
SPEC = '5bcf511e604579afa63f434013447f44b6858828'


def proof_input(record, key):
    parts = record['id'].split(':')
    require(parts[:3] == ['did', 'sage', 'eip155'] and
            len(parts) == 6 and parts[-1] == 'alice',
            'fixed public chain DID')
    values = [':'.join(parts[2:-1]).encode(), parts[-1].encode(),
              key['name'].encode(), key['alg'].encode(), decoded(key['key'])]
    return b'sage-pop-0.10.0' + b''.join(
        len(value).to_bytes(2, 'big') + value for value in values)


def verify_proofs(record):
    signer = next(key for key in record['keys'] if key['name'] == 'signing-1')
    require(signer['alg'] == 'ed25519' and signer['state'] == 'accepted',
            'accepted signing proof key')
    public = Ed25519PublicKey.from_public_bytes(decoded(signer['key']))
    for key in record['keys']:
        require(key['proof']['signer'] == record['id'] + '#signing-1'
                and len(decoded(key['key'])) == 32,
                'fixed same-record proof signer and public key')
        public.verify(decoded(key['proof']['value']), proof_input(record, key))


def apply(inp):
    """Expected state transition only; never a subject implementation result."""
    record = inp['record']
    version = int(record['version'])
    if (inp['actor'] != record['controller'] or
            inp['expected_version'] != record['version'] or
            version == 2**64 - 1 or record['state'] == 'deactivated'):
        return {'verdict': 'REJECT', 'output': {},
                'effects': {'mutations': 0}}
    if inp['operation'] == 'lifecycle-transition':
        allowed = {('created', 'active'), ('created', 'deactivated'),
                   ('active', 'deactivated')}
        if (record['state'], inp['new_state']) not in allowed:
            return {'verdict': 'REJECT', 'output': {},
                    'effects': {'mutations': 0}}
        state = inp['new_state']
    elif inp['operation'] == 'update-services' and record['state'] == 'active':
        require(inp['services'] == record['services'], 'fixed service control')
        state = 'active'
    else:
        return {'verdict': 'REJECT', 'output': {},
                'effects': {'mutations': 0}}
    return {'verdict': 'ACCEPT',
            'output': {'version': str(version + 1), 'state': state},
            'effects': {'mutations': 1}}


def check(root=ROOT):
    original_raw = (root / ORIGINAL).read_bytes()
    original = load(original_raw)
    steps = original['steps']
    raw = (root / SOURCE).read_bytes()
    suite = load(raw)
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == sha(original_raw)
            and tuple(row['id'] for row in suite['cases']) == IDS
            and tuple(row['name'] for row in suite['supplemental']) ==
                ('version-ceiling', 'terminal-deactivate'),
            'REG-03 source, revision, and case identity')
    initial = steps[0]['input']['record']
    verify_proofs(initial)
    require(initial['state'] == 'created' and initial['version'] == '1'
            and steps[5]['expected']['output'] ==
                {'version': '2', 'state': 'active'}
            and steps[9]['expected']['output'] ==
                {'version': '3', 'state': 'deactivated'},
            'audited independent lifecycle source')
    for row in suite['cases']:
        ident = row['id']
        index = STEPS[ident]
        step = steps[index]
        inp = row['input']
        record = inp['record']
        require(row['source_step'] == step['id'] and
                step['input']['action'] == 'mutate' and
                inp['operation'] == 'lifecycle-transition' and
                inp['expected_version'] == step['input']['expected_version'] and
                inp['new_state'] == step['input']['new_state'] and
                (inp['actor'] == record['controller']) ==
                    step['input']['authorized'] and
                {**record, 'state': 'created', 'version': '1'} == initial,
                'isolated source step: ' + ident)
        expected_state = {'REG-03-P': ('created', '1'),
                          'REG-03-N01': ('created', '1'),
                          'REG-03-N02': ('active', '2'),
                          'REG-03-N03': ('deactivated', '3'),
                          'REG-03-N04': ('created', '1')}[ident]
        require((record['state'], record['version']) == expected_state
                and apply(inp) == row['expected'] and
                row['expected']['verdict'] == step['expected']['verdict'],
                'atomic transition and unchanged rejection: ' + ident)
        if ident in ('REG-03-N02', 'REG-03-N03'):
            prior = steps[5 if ident == 'REG-03-N02' else 9]
            require(inp['prior_commit'] == {
                'step_id': prior['id'], 'input': prior['input'],
                'expected': prior['expected']} and
                prior['expected']['verdict'] == 'ACCEPT',
                'accepted prior commit before rejected attempt: ' + ident)
        else:
            require('prior_commit' not in inp,
                    'isolated initial-state attempt: ' + ident)
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.registry.lifecycle.apply',
                                      'input': inp},
                            'expected': row['expected']},
                'REG-03 runtime fixture contract: ' + ident)
    controls = {row['name']: row for row in suite['supplemental']}
    ceiling = controls['version-ceiling']['input']
    terminal = controls['terminal-deactivate']['input']
    require(ceiling['record']['version'] == str(2**64 - 1) and
            apply(ceiling)['verdict'] == controls['version-ceiling']['expected']
            and terminal['record']['state'] == 'active'
            and terminal['record']['version'] == '2'
            and apply(terminal)['verdict'] ==
                controls['terminal-deactivate']['expected'],
            'version ceiling and terminal transition controls')
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(manifest['spec_revision'] == SPEC and
            manifest['source_sha256']['spec/09-registry.md'] ==
                '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
            'pinned current lifecycle chapter')
    return len(IDS), len(controls)


if __name__ == '__main__':
    print('Verified REG-03 cases and controls:', check())
