"""Check SESSION-06 closure fixtures against independent scenario boundaries."""

from current_spec_catalog import ROOT, load, require, sha


IDS = ('SESSION-06-P', 'SESSION-06-N01', 'SESSION-06-N02',
       'SESSION-06-N03', 'SESSION-06-N04', 'SESSION-06-N05')
BASE = 'vectors/0.10.0/session-scenarios/'
SOURCES = {
    'SESSION-06-P': 'session-close',
    'SESSION-06-N01': 'session-registry-revoked-init-key',
    'SESSION-06-N02': 'session-registry-unavailable',
    'SESSION-06-N03': 'session-registry-expired',
    'SESSION-06-N04': 'session-restart',
    'SESSION-06-N05': 'session-close',
}
OPERATIONS = {
    'SESSION-06-P': 'sage.session.fresh_handshake_after_close.verify',
    'SESSION-06-N01': 'sage.session.revoked_key.verify',
    'SESSION-06-N02': 'sage.session.registry_unavailable.verify',
    'SESSION-06-N03': 'sage.session.expired_key.verify',
    'SESSION-06-N04': 'sage.session.restored_counter.verify',
    'SESSION-06-N05': 'sage.session.plaintext_fallback.verify',
}


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-06 fixture identity')
    raw = {name: (root / BASE / (name + '.json')).read_bytes()
           for name in set(SOURCES.values())}
    steps = {name: load(value)['steps'] for name, value in raw.items()}
    close = steps['session-close']
    restart = steps['session-restart']
    require(close[3]['input']['action'] == 'close' and
            close[4]['expected']['output']['state'] == 'CLOSED' and
            close[4]['expected']['output']['keys_available'] is False and
            close[5]['expected'] == {'verdict': 'REJECT', 'output': {}} and
            close[7]['expected'] == {'verdict': 'REJECT', 'output': {}} and
            restart[3]['input']['action'] == 'restart' and
            restart[4]['expected']['output']['keys_available'] is False and
            restart[5]['expected']['verdict'] == 'REJECT',
            'independent close and restart scenarios')
    for name in ('session-registry-revoked-init-key',
                 'session-registry-unavailable', 'session-registry-expired'):
        scenario = steps[name]
        require(scenario[1]['input']['action'] == 'registry' and
                scenario[2]['expected']['output']['state'] == 'CLOSED' and
                scenario[2]['expected']['output']['keys_available'] is False and
                scenario[3]['expected']['verdict'] == 'REJECT',
                'independent registry closure scenario: ' + name)
    source = (root / 'verification/0.10.0/snapshot/spec/05-session.md').read_text()
    require('No restored state may reset counters' in source and
            'fresh authenticated handshake' in source and
            'plaintext fallback or reuse of retired keys' in source,
            'pinned SESSION-06 restoration and fallback rule')
    for ident in IDS:
        name = SOURCES[ident]
        require(fixtures[ident]['input'] == {'operation': OPERATIONS[ident],
            'input': {'scenario_id': name, 'scenario_sha256': sha(raw[name])}} and
            fixtures[ident]['expected'] == {'verdict':
                'ACCEPT' if ident == 'SESSION-06-P' else 'REJECT',
                'output': {'fresh_session': True} if ident == 'SESSION-06-P' else {},
                'effects': {}}, 'SESSION-06 fixture relation: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-06 closure fixtures:', check())
