"""Generate manifest, signed-result, and MCP representation probes."""

import copy
import hashlib
import json
from pathlib import Path

import generate_guard_vectors as guard


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-06-P', 'EXEC-06-N03', 'EXEC-07-P', 'EXEC-07-N01',
       'EXEC-07-N02', 'EXEC-07-N03', 'EXEC-07-N05', 'EXEC-08-P',
       'EXEC-08-N06')


def cases():
    historical = {row['id']: row for row in json.loads(
        (ROOT / 'vectors/0.10.0/guard-records.json').read_text())['cases']}
    mcp = {row['id']: row for row in json.loads(
        (ROOT / 'vectors/0.10.0/guard-mcp.json').read_text())['cases']}
    result = historical['result-completed-valid']['input']
    wrong_issuer = copy.deepcopy(result)
    envelope = json.loads(bytes.fromhex(result['envelope_hex']))
    envelope['result']['issuer'] = guard.ISSUER
    envelope['proof'] = guard.b64(guard.RK.sign(
        b'sage-tool-result|0.10.0\x00' + guard.jcs(envelope['result'])))
    wrong_issuer['envelope_hex'] = guard.jcs(envelope).hex()
    bad_proof = copy.deepcopy(result)
    envelope = json.loads(bytes.fromhex(result['envelope_hex']))
    proof = envelope['proof']
    envelope['proof'] = ('A' if proof[0] != 'A' else 'B') + proof[1:]
    bad_proof['envelope_hex'] = guard.jcs(envelope).hex()
    mapping = (
        ('EXEC-06-P', 'manifest-valid'),
        ('EXEC-06-N03', 'manifest-hash'),
        ('EXEC-07-P', 'result-completed-valid'),
        ('EXEC-07-N01', None),
        ('EXEC-07-N02', 'result-completed-wrong-intent'),
        ('EXEC-07-N03', 'result-completed-expired'),
        ('EXEC-07-N05', None),
        ('EXEC-08-P', None),
        ('EXEC-08-N06', None),
    )
    rows = []
    for ident, prior in mapping:
        if ident == 'EXEC-07-N01':
            inp, operation = wrong_issuer, 'sage.guard.result.verify'
        elif ident == 'EXEC-07-N05':
            inp, operation = bad_proof, 'sage.guard.result.verify'
        elif ident in ('EXEC-08-P', 'EXEC-08-N06'):
            name = 'completed' if ident == 'EXEC-08-P' else 'mismatch'
            inp, operation = mcp[name]['input'], 'sage.guard.mcp.verify'
        else:
            inp, operation = historical[prior]['input'], historical[prior]['operation']
        verdict = 'ACCEPT' if ident.endswith('-P') else 'REJECT'
        output = ({'manifest_digest': guard.sha(guard.jcs(guard.MANIFEST))}
                  if ident == 'EXEC-06-P' else
                  {'success': True, 'error': '', 'status': 'completed',
                   'wire_hex': inp['wire_hex']} if ident == 'EXEC-08-P' else
                  {'valid': True} if verdict == 'ACCEPT' else {})
        rows.append((ident, operation, inp,
                     {'verdict': verdict, 'output': output, 'effects': {}}))
    return rows


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f',
             'mcp_bytes_sha256': hashlib.sha256((ROOT / 'vectors/0.10.0/guard-mcp.json').read_bytes()).hexdigest(),
             'scope': 'manifest bytes, signed result primitives, and MCP representation only; no loaded-instance, durable consumption, or mandatory interception claim',
             'cases': []}
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, operation, inp, expected in cases():
        wrapped = {'operation': operation, 'input': inp}
        suite['cases'].append({'id': ident, 'input': wrapped, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': wrapped, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-results.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
