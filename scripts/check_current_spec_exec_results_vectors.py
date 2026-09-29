"""Independently audit manifest, signed result, and MCP wire cases."""

import base64
import copy
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-06-P', 'EXEC-06-N03', 'EXEC-07-P', 'EXEC-07-N01',
       'EXEC-07-N02', 'EXEC-07-N03', 'EXEC-07-N05', 'EXEC-08-P',
       'EXEC-08-N06')
SOURCE = 'vectors/0.10.0/exec-results.json'


def signature_valid(inp):
    envelope = load(bytes.fromhex(inp['envelope_hex']))
    signature = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
    message = b'sage-tool-result|0.10.0\x00' + json.dumps(
        envelope['result'], sort_keys=True, separators=(',', ':')).encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(
            inp['public_key_hex'])).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-records.json').read_bytes()) ==
            '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f' and
            suite['mcp_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-mcp.json').read_bytes()) ==
            'df2e965ade565d989077475df9d1648013b1169e3b8c21ae9db0ce36c63c6754' and
            suite['scope'] == 'manifest bytes, signed result primitives, and MCP representation only; no loaded-instance, durable consumption, or mandatory interception claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'execution manifest, result, MCP source identity')
    inputs = [row['input']['input'] for row in suite['cases']]
    good_manifest, bad_manifest = inputs[:2]
    files = good_manifest['manifest']['files']
    require(len(files) == len(good_manifest['artifacts']) == 2 and
            all(row['path'] == artifact['path'] and
                row['sha256'] == hashlib.sha256(bytes.fromhex(
                    artifact['bytes_hex'])).hexdigest()
                for row, artifact in zip(files, good_manifest['artifacts'])) and
            bad_manifest['artifacts'] == good_manifest['artifacts'],
            'exact approved artifact bytes')
    changed_manifest = copy.deepcopy(good_manifest['manifest'])
    changed_manifest['files'][0]['sha256'] = '0' * 64
    require(bad_manifest['manifest'] == changed_manifest,
            'single changed manifest hash')
    canonical = json.dumps(good_manifest['manifest'], sort_keys=True,
                           separators=(',', ':')).encode()
    manifest_sha = hashlib.sha256(canonical).hexdigest()
    normal, issuer, intent, expired, bad_proof = inputs[2:7]
    value = load(bytes.fromhex(normal['envelope_hex']))
    wrong_issuer = load(bytes.fromhex(issuer['envelope_hex']))
    wrong_intent = load(bytes.fromhex(intent['envelope_hex']))
    require(all(signature_valid(row) for row in
                (normal, issuer, intent, expired)) and
            not signature_valid(bad_proof) and
            wrong_issuer['result'] == dict(value['result'],
                                           issuer=value['result']['recipient']) and
            wrong_intent['result'] == dict(value['result'],
                                           intent_digest='0' * 64) and
            expired['envelope_hex'] == normal['envelope_hex'] and
            expired['now'] == value['result']['expires'] and
            load(bytes.fromhex(bad_proof['envelope_hex']))['result'] ==
            value['result'],
            'independent result signatures and isolated defects')
    mcp_good, mcp_bad = inputs[7:]
    wire = load(bytes.fromhex(mcp_good['wire_hex']))
    mismatch = load(bytes.fromhex(mcp_bad['wire_hex']))
    require(mcp_good['mcp_version'] == mcp_bad['mcp_version'] == '2025-06-18' and
            wire['structuredContent'] == mismatch['structuredContent'] == value and
            wire['content'][0]['text'] == json.dumps(value, sort_keys=True,
                                                    separators=(',', ':')) and
            mismatch['content'][0]['text'] == '{}' and
            wire['isError'] is mismatch['isError'] is False,
            'MCP canonical structured/text agreement and isolated mismatch')
    expected = []
    for ident, row in zip(IDS, suite['cases']):
        verdict = 'ACCEPT' if ident.endswith('-P') else 'REJECT'
        output = ({'manifest_digest': manifest_sha} if ident == 'EXEC-06-P' else
                  {'success': True, 'error': '', 'status': 'completed',
                   'wire_hex': mcp_good['wire_hex']} if ident == 'EXEC-08-P' else
                  {'valid': True} if verdict == 'ACCEPT' else {})
        expected.append({'verdict': verdict, 'output': output, 'effects': {}})
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['expected'] == expected[index] and fixture == {
            'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
            'track': 'runtime', 'input': row['input'],
            'expected': expected[index]},
            'execution result case contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'execution result partial runtime binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
