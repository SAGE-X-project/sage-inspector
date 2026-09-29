#!/usr/bin/env python3
"""Observe denial after a bounded local Guard ledger becomes unavailable."""

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


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def invoke(adapter, journal, mode, commands):
    wire = ''.join(json.dumps(action, separators=(',', ':')) + '\n'
                   for action in commands).encode()
    require(len(wire) <= 1024 * 1024, 'bounded Guard input')
    result = subprocess.run([str(adapter), str(journal), mode],
                            input=wire, capture_output=True, timeout=10,
                            check=False)
    require(len(result.stdout) <= 1024 * 1024 and
            len(result.stderr) <= 1024, 'bounded Guard output')
    return result


def observe(raw, adapter):
    request = load(raw)
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id', 'track', 'input'} and
            request['schema_version'] == 1 and request['track'] == 'runtime' and
            request['spec_revision'] == catalog()[0]['spec_revision'] and
            type(request['id']) is str and
            re.fullmatch('[A-Za-z0-9-]+', request['id']) is not None and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'case request and adapter')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'input'} and
            inp['operation'] == 'sage.guard.dispatch.missing-ledger' and
            type(inp['input']) is dict and
            set(inp['input']) == {'configuration', 'envelope_hex'},
            'missing-ledger operation')
    configuration = inp['input']['configuration']
    envelope = inp['input']['envelope_hex']
    require(type(configuration) is dict and type(envelope) is str and
            configuration.get('envelope_hex') == envelope and
            len(envelope) <= 65536 and
            re.fullmatch('[0-9a-f]+', envelope) is not None,
            'exact signed Guard intent')
    config = {'action': 'configure', 'input': configuration,
              'instance': 'old'}
    dispatch = {'action': 'dispatch', 'envelope_hex': envelope}
    with tempfile.TemporaryDirectory(prefix='sage-lost-ledger-current-') as temporary:
        journal = Path(temporary) / 'ledger'
        retained = Path(temporary) / 'retained-ledger'
        first = invoke(adapter, journal, 'create', [config, dispatch])
        require(first.returncode == 0 and not first.stderr and
                len(first.stdout.splitlines()) == 2 and
                journal.is_file() and not journal.is_symlink(),
                'initial inert Guard dispatch')
        rows = [load(line) for line in first.stdout.splitlines()]
        before = journal.read_bytes()
        require(before.startswith(b'sage-execution-ledger|0.10.0\n') and
                before.endswith(b'\n') and len(before) <= 1024 * 1024 and
                rows[0].get('ok') is True and
                rows[1].get('ok') is True and
                rows[1].get('committed') is True and
                type(rows[1].get('effects')) is list,
                'committed dispatch and durable ledger')
        states = [load(line)['state'] for line in
                  before[len(b'sage-execution-ledger|0.10.0\n'):].splitlines()]
        os.replace(journal, retained)
        second = invoke(adapter, journal, 'reopen', [config, dispatch])
        require(not second.stderr, 'reopen diagnostics')
        recreated = journal.exists() or journal.with_name('ledger.lock').exists()
        unchanged = retained.read_bytes() == before
    actual = {'verdict': 'REJECT' if second.returncode else 'ACCEPT',
              'output': {'before_states': states,
                         'reopen_exit': second.returncode,
                         'reopen_stdout_empty': not second.stdout,
                         'journal_recreated': recreated,
                         'retained_history_unchanged': unchanged,
                         'post_loss_effects': 0 if not second.stdout else
                             max(len(load(line).get('effects', []))
                                 for line in second.stdout.splitlines())},
              'effects': {'dispatch_before_loss': len(rows[1]['effects']),
                          'dispatch_after_loss': 0 if not second.stdout else
                              max(len(load(line).get('effects', []))
                                  for line in second.stdout.splitlines())}}
    validate_outcome(actual)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': actual}


def main():
    try:
        adapter = os.environ.get('SAGE_CORE_ADAPTER')
        require(adapter and Path(adapter).is_absolute(),
                'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'case request exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(adapter)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print('Current spec missing-ledger bridge FAIL: ' + str(error),
              file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
