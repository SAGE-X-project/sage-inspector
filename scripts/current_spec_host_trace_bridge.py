#!/usr/bin/env python3
"""Classify a version-pinned host's bounded observation for one EXEC case."""

import json
import os
from pathlib import Path
import subprocess
import sys

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome
from current_spec_host_probe import CONTRACTS, inspect


def observe(raw, adapter):
    request = load(raw)
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == catalog()[0]['spec_revision'] and
            request['track'] == 'runtime' and request['id'] in CONTRACTS and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'host case and subject identity')
    payload = request['input']
    require(type(payload) is dict and
            set(payload) == {'operation', 'input'} and
            payload['operation'] == 'sage.host.execution.trace' and
            payload['input'] == {'case_id': request['id'],
                                 'trigger': CONTRACTS[request['id']]['trigger']},
            'pinned host probe')
    proc = subprocess.run([str(adapter)], input=json.dumps(payload['input']).encode(),
                          capture_output=True, timeout=20, check=False)
    require(proc.returncode == 0 and not proc.stderr and
            len(proc.stdout) <= 16 * 1024, 'bounded host observation')
    actual = inspect(request['id'], load(proc.stdout))
    validate_outcome(actual)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': actual}


def main():
    try:
        adapter = os.environ.get('SAGE_CORE_ADAPTER')
        require(adapter and Path(adapter).is_absolute(),
                'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        require(len(raw) <= 16 * 1024, 'host case input exceeds 16 KiB')
        print(json.dumps(observe(raw, Path(adapter)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Current spec host trace FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
