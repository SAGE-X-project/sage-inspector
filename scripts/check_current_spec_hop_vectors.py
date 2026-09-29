"""Audit signed hop fixtures and partial bindings against pinned sources."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_hop_vectors import IDS, SPEC, cases


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()


def verify(hex_bytes, public):
    raw = bytes.fromhex(hex_bytes)
    envelope = load(raw)
    proof = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                     (-len(envelope['proof']) % 4))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
        proof, b'sage-execution-intent|0.10.0\x00' + canonical(envelope['intent']))
    require(raw == canonical(envelope), 'canonical signed envelope')
    return envelope['intent']


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/exec-hop.json').read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    source = root / 'vectors/0.10.0/guard-client.json'
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['source_bytes_sha256'] == sha(source.read_bytes()) and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned hop sources and case IDs')
    for row, (ident, inp, output) in zip(suite['cases'], cases()):
        expected = {'verdict': 'ACCEPT' if output['opened'] else 'REJECT',
                    'output': output, 'effects': {'handoff': output['handoffs']}}
        payload = {'operation': 'sage.guard.hop.open', 'input': inp}
        require(row == {'id': ident, 'input': payload, 'expected': expected},
                'hop fixture expectation: ' + ident)
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (root / relative).read_bytes()
        require(load(raw) == {'schema_version': 1, 'spec_revision': SPEC,
                              'id': ident, 'track': 'runtime',
                              'input': payload, 'expected': expected} and
                any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': relative, 'fixture_sha256': sha(raw),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'hop partial binding: ' + ident)
        upstream = verify(inp['incoming_hex'], inp['parent']['public_key_hex'])
        child = verify(inp['outgoing_hex'], inp['child']['public_key_hex'])
        incoming = bytes.fromhex(inp['incoming_hex'])
        capture = (b'sage-original|0.10.0\x00' + (1).to_bytes(4, 'big') +
                   len(incoming).to_bytes(8, 'big') + incoming)
        require(upstream['recipient'] == child['issuer'] and
                child['recipient'] == upstream['issuer'] and
                child['parent_call_id'] == upstream['call_id'] and
                child['request_id'] != upstream['request_id'] and
                child['call_id'] != upstream['call_id'] and
                child['original_digest'] == hashlib.sha256(capture).hexdigest() and
                child['policy_digest'] == hashlib.sha256(
                    b'sage-policy|0.10.0\x00' +
                    canonical(inp['child']['approved_policy'])).hexdigest(),
                'fresh exact B-to-C lineage and independent policy')
    require(suite['cases'][0]['input']['input']['parent_allowed'] is True and
            suite['cases'][0]['input']['input']['child']['policy_allow'] is True and
            suite['cases'][1]['input']['input']['child']['policy_allow'] is False and
            suite['cases'][2]['input']['input']['parent_allowed'] is False,
            'independent parent and child decisions')
    return len(IDS)


if __name__ == '__main__':
    print(check())
