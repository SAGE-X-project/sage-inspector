#!/usr/bin/env python3
"""Observe bounded signed Guard result lifecycles using an inert core sink."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def verified_result(envelope_hex, public_key_hex, intent_sha):
    envelope = load(bytes.fromhex(envelope_hex))
    require(set(envelope) == {'result', 'proof'} and
            type(envelope['result']) is dict and
            type(envelope['proof']) is str, 'signed result envelope')
    signature = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            signature, b'sage-tool-result|0.10.0\x00' + jcs(envelope['result']))
        valid = envelope['result'].get('intent_digest') == intent_sha
    except InvalidSignature:
        valid = False
    return envelope['result'].get('status', ''), valid


def summarize(row, public_key_hex, intent_sha):
    require(type(row) is dict and set(row) == {
        'ok', 'created', 'committed', 'state', 'intent_digest',
        'effects', 'signs', 'result_hex'} and
        all(type(row[name]) is bool for name in ('ok', 'created', 'committed')) and
        type(row['state']) is str and type(row['intent_digest']) is str and
        type(row['signs']) is int and 0 <= row['signs'] <= 20 and
        type(row['result_hex']) is str and
        type(row['effects']) is list and len(row['effects']) <= 2,
        'invalid result fixture reply')
    status, signature_valid = ('', False)
    if row['result_hex']:
        status, signature_valid = verified_result(
            row['result_hex'], public_key_hex, intent_sha)
    effect_hashes = [sha(jcs(effect)) for effect in row['effects']]
    return {name: row[name] for name in ('ok', 'created', 'committed',
                                         'state', 'intent_digest', 'signs')} | {
        'result_status': status,
        'result_signature_valid': signature_valid,
        'effect_sha256': effect_hashes}


def observe(raw, adapter):
    request = load(raw)
    spec_revision = catalog()[0]['spec_revision']
    require(type(request) is dict and set(request) == {'schema_version',
            'spec_revision', 'id', 'track', 'input'} and
            request['schema_version'] == 1 and request['track'] == 'runtime' and
            request['spec_revision'] == spec_revision and
            type(request['id']) is str and
            re.fullmatch('[A-Za-z0-9-]+', request['id']) is not None,
            'case request identity')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'input'} and
            inp['operation'] == 'sage.guard.result.sequence' and
            type(inp['input']) is dict and
            set(inp['input']) == {'actions', 'public_key_hex'},
            'result lifecycle operation')
    actions, public_key_hex = (inp['input']['actions'],
                               inp['input']['public_key_hex'])
    require(type(actions) is list and 2 <= len(actions) <= 12 and
            type(public_key_hex) is str and
            re.fullmatch('[0-9a-f]{64}', public_key_hex) is not None and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'bounded actions and core binary')
    require(type(actions[0]) is dict and
            actions[0].get('action') == 'configure' and
            type(actions[0].get('input')) is dict and
            type(actions[0]['input'].get('envelope_hex')) is str,
            'configured signed intent')
    intent_envelope = bytes.fromhex(actions[0]['input']['envelope_hex'])
    intent_sha = sha(intent_envelope)
    for action in actions:
        require(type(action) is dict and action.get('action') in
                ('configure', 'dispatch', 'reply', 'finish', 'reject', 'signer'),
                'unrecognized inert result action')
    wire = ''.join(json.dumps(action, separators=(',', ':')) + '\n'
                   for action in actions).encode()
    require(len(wire) <= 1024 * 1024, 'result input exceeds 1 MiB')
    with tempfile.TemporaryDirectory(prefix='sage-results-current-') as temporary:
        journal = Path(temporary) / 'ledger'
        proc = subprocess.run([str(adapter), str(journal), 'create'],
                              input=wire, capture_output=True, timeout=10,
                              check=False)
        require(proc.returncode == 0 and not proc.stderr and
                len(proc.stdout) <= 1024 * 1024,
                'core result fixture failed')
        rows = [load(line) for line in proc.stdout.splitlines()]
        require(len(rows) == len(actions), 'missing result reply')
        summaries = [summarize(row, public_key_hex, intent_sha) for row in rows]
        require(journal.is_file() and not journal.is_symlink(),
                'missing durable result ledger')
        lines = journal.read_bytes().splitlines()
        require(lines and lines[0] == b'sage-execution-ledger|0.10.0' and
                len(lines) <= 32 and sum(map(len, lines)) <= 1024 * 1024,
                'unexpected result ledger')
        stored = [load(line) for line in lines[1:]]
    terminal = [row for row in stored if row.get('result_hex')]
    stored_hex = terminal[-1]['result_hex'] if terminal else ''
    stored_status, stored_valid = ('', False)
    if stored_hex:
        stored_status, stored_valid = verified_result(
            stored_hex, public_key_hex, intent_sha)
    published = [row['result_hex'] for row in rows if row['result_hex'] and
                 load(bytes.fromhex(row['result_hex']))['result']['status'] != 'pending']
    result = {'verdict': 'ACCEPT' if rows[-1]['ok'] else 'REJECT',
              'output': {'rows': summaries,
                         'journal_states': [row['state'] for row in stored],
                         'stored_result_status': stored_status,
                         'stored_result_signature_valid': stored_valid,
                         'published_terminal_matches_storage':
                             bool(published) and
                             all(value == stored_hex for value in published)},
              'effects': {'dispatch': max(len(row['effects']) for row in rows)}}
    validate_outcome(result)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': result}


def main():
    try:
        path = os.environ.get('SAGE_CORE_ADAPTER')
        require(path and Path(path).is_absolute(), 'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'case request exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(path)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print('Current spec Guard result bridge FAIL: ' + str(error),
              file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
