"""Check declarative receive and replay-state scenarios without traffic."""

import base64
import copy
import json

from current_spec_catalog import ROOT, load, require, sha
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-04-P', 'TRANSPORT-04-N01', 'TRANSPORT-04-N02',
       'TRANSPORT-04-N03', 'TRANSPORT-04-N04')
SOURCE = 'vectors/0.10.0/transport04-scenarios.json'


def envelope(row):
    return load(bytes.fromhex(row['input']['request_hex'])
                .split(b'\r\n\r\n', 1)[1])


def signed(value, public):
    unsigned = copy.deepcopy(value)
    signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
    message = b'sage-wire-request|0.10.0\n' + json.dumps(
        unsigned, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    return verified(public, signature, message)


def model(scenario, source):
    """Unit-only atomic reservation model; never sends or opens a message."""
    if scenario['id'] == 'TRANSPORT-04-N03':
        require(scenario['session_record_case'] == 'tag' and
                scenario['preconditions'] == {
                    'outer_verified': True, 'inner_verified': True},
                'session tag failure precondition')
        return 0, 1, 0, 0
    first = source[scenario['source_http_case']]
    if first['expected']['verdict'] == 'REJECT':
        return 0, 1, 0, 0
    original = envelope(first)
    reserved_ids = set()
    accepted = rejected = dispatches = 0
    arrivals = [original] * scenario['deliveries']
    if scenario['id'] == 'TRANSPORT-04-N04':
        arrivals[1] = load(bytes.fromhex(scenario['second_signed_envelope_hex']))
    for item in arrivals:
        if item['id'] in reserved_ids:
            rejected += 1
        else:
            reserved_ids.add(item['id'])
            accepted += 1
            dispatches += 1
    return accepted, rejected, len(reserved_ids), dispatches


def check(root=ROOT):
    raw = (root / SOURCE).read_bytes()
    suite = load(raw)
    http_raw = (root / 'vectors/0.10.0/http-boundaries.json').read_bytes()
    record_raw = (root / 'vectors/0.10.0/session-records.json').read_bytes()
    http = {row['id']: row for row in load(http_raw)['cases']}
    records = {row['id']: row for row in load(record_raw)['cases']}
    proofs = load((root / 'docs/evidence/http-boundary-proofs.json').read_bytes())
    scenarios = {row['id']: row for row in suite['scenarios']}
    require(suite['schema_version'] == 1 and
            suite['source_sha256'] == {'http': sha(http_raw),
                                       'session_records': sha(record_raw)} and
            tuple(scenarios) == IDS and
            proofs['valid-request']['reason'] is None and
            proofs['request-inner-signature']['reason'] == 'inner-signature'
            and records['tag']['operation'] == 'sage.session.record.open' and
            records['tag']['expected']['verdict'] == 'REJECT',
            'TRANSPORT-04 independent source evidence')
    public = bytes.fromhex(http['valid-request']['input']['public_key_hex'])
    control = envelope(http['valid-request'])
    require(signed(control, public), 'TRANSPORT-04 signed control')
    require(scenarios['TRANSPORT-04-N01']['source_http_case'] ==
            'request-inner-signature' and
            scenarios['TRANSPORT-04-N02']['concurrent'] is True and
            scenarios['TRANSPORT-04-N02']['deliveries'] == 2 and
            scenarios['TRANSPORT-04-N04']['concurrent'] is False and
            scenarios['TRANSPORT-04-N04']['deliveries'] == 2,
            'TRANSPORT-04 rejected inner and duplicate scenarios')
    second = load(bytes.fromhex(scenarios['TRANSPORT-04-N04']
                                 ['second_signed_envelope_hex']))
    other = copy.deepcopy(second)
    other.pop('nonce')
    other.pop('signature')
    baseline = copy.deepcopy(control)
    baseline.pop('nonce')
    baseline.pop('signature')
    require(other == baseline and second['nonce'] != control['nonce'] and
            signed(second, public) and
            scenarios['TRANSPORT-04-N04']['second_outer_binding'] ==
                'simulated_precondition',
            'TRANSPORT-04 same signed id with a new nonce')
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    for ident in IDS:
        scenario = scenarios[ident]
        accepted, rejected, reserved, dispatches = model(scenario, http)
        require((accepted, rejected, reserved, dispatches) ==
                tuple(scenario[key] for key in ('expected_accepts',
                     'expected_rejects', 'expected_reservations',
                     'expected_dispatches')),
                'TRANSPORT-04 unit reservation model: ' + ident)
        expected = {
            'verdict': 'ACCEPT' if ident == 'TRANSPORT-04-P' else 'REJECT',
            'output': {'accepted': accepted, 'rejected': rejected},
            'effects': {'replay_reservations': reserved,
                        'application_dispatches': dispatches},
        }
        require(fixtures[ident]['id'] == ident and
                fixtures[ident]['track'] == 'runtime' and
                fixtures[ident]['input'] == {
                    'operation': 'sage.transport.receive.scenario',
                    'input': {'scenario_id': ident, 'scenario_sha256': sha(raw)}}
                and fixtures[ident]['expected'] == expected,
                'TRANSPORT-04 fixture contract: ' + ident)
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('cryptographic acceptance atomically reserves id/nonce' in spec
            and 'A different nonce does not make an already accepted id' in spec
            and 'Application rejection does not release' in spec,
            'pinned TRANSPORT-04 receive transaction rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified TRANSPORT-04 declarative scenarios:', check())
