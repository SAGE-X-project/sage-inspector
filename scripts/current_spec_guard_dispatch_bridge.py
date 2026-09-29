#!/usr/bin/env python3
"""Run bounded Guard dispatch sequences against an inert core fixture sink."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                               separators=(',', ':')).encode()).hexdigest()


def summarize(row):
    require(type(row) is dict and set(row) == {'ok', 'created', 'committed',
                                               'state', 'intent_digest', 'effects'} and
            all(type(row[name]) is bool for name in ('ok', 'created', 'committed')) and
            type(row['state']) is str and
            row['state'] in ('', 'EXECUTING', 'UNKNOWN') and
            type(row['intent_digest']) is str and
            type(row['effects']) is list and len(row['effects']) <= 2,
            'invalid dispatch reply')
    for effect in row['effects']:
        require(type(effect) is dict and set(effect) == {
            'instance', 'envelope_hex', 'arguments_hex', 'tool',
            'manifest_digest', 'intent_digest'} and
            all(type(value) is str for value in effect.values()),
            'invalid inert effect')
    return {name: row[name] for name in ('ok', 'created', 'committed',
                                         'state', 'intent_digest')} | {
        'effect_sha256': [digest(effect) for effect in row['effects']]}


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
            inp['operation'] == 'sage.guard.dispatch.sequence' and
            type(inp['input']) is dict and
            set(inp['input']) == {'stages'}, 'dispatch operation')
    stages = inp['input']['stages']
    require(type(stages) is list and 1 <= len(stages) <= 2 and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'bounded stages and core binary')
    all_rows = []
    dispatch_count = 0
    with tempfile.TemporaryDirectory(prefix='sage-guard-current-') as temporary:
        journal = Path(temporary) / 'ledger'
        for index, stage in enumerate(stages):
            require(type(stage) is dict and set(stage) == {'mode', 'actions'} and
                    stage['mode'] == ('create' if index == 0 else 'reopen') and
                    type(stage['actions']) is list and
                    1 <= len(stage['actions']) <= 4,
                    'bounded dispatch stage')
            for action in stage['actions']:
                require(type(action) is dict and action.get('action') in
                        ('configure', 'dispatch', 'retire'),
                        'unrecognized inert action')
            wire = ''.join(json.dumps(action, separators=(',', ':')) + '\n'
                           for action in stage['actions']).encode()
            require(len(wire) <= 1024 * 1024, 'dispatch input exceeds 1 MiB')
            proc = subprocess.run([str(adapter), str(journal), stage['mode']],
                                  input=wire, capture_output=True, timeout=10,
                                  check=False)
            require(proc.returncode == 0 and not proc.stderr and
                    len(proc.stdout) <= 1024 * 1024,
                    'core dispatch fixture failed')
            rows = [load(line) for line in proc.stdout.splitlines()]
            require(len(rows) == len(stage['actions']), 'missing dispatch reply')
            dispatch_count += max(len(row['effects']) for row in rows)
            all_rows.append([summarize(row) for row in rows])
        require(journal.is_file() and not journal.is_symlink(),
                'missing durable ledger')
        lines = journal.read_bytes().splitlines()
        require(lines and lines[0] == b'sage-execution-ledger|0.10.0' and
                len(lines) <= 32 and sum(map(len, lines)) <= 1024 * 1024,
                'unexpected durable ledger')
        states = [load(line)['state'] for line in lines[1:]]
    actual = {'verdict': 'ACCEPT' if all_rows[-1][-1]['ok'] else 'REJECT',
              'output': {'stages': all_rows, 'journal_states': states},
              'effects': {'dispatch': dispatch_count}}
    validate_outcome(actual)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': actual}


def main():
    try:
        path = os.environ.get('SAGE_CORE_ADAPTER')
        require(path and Path(path).is_absolute(), 'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'case request exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(path)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print('Current spec Guard dispatch bridge FAIL: ' + str(error),
              file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
