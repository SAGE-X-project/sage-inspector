#!/usr/bin/env python3
"""Observe a bounded signed hop through an explicit local core binary."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome
from generate_current_spec_hop_vectors import IDS


def observe(raw, adapter):
    request = load(raw)
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == catalog()[0]['spec_revision'] and
            request['track'] == 'runtime' and request['id'] in IDS and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'hop request and adapter identity')
    payload = request['input']
    require(type(payload) is dict and
            set(payload) == {'operation', 'input'} and
            payload['operation'] == 'sage.guard.hop.open' and
            type(payload['input']) is dict and
            set(payload['input']) == {'incoming_hex', 'outgoing_hex',
                                      'parent', 'child', 'parent_allowed',
                                      'begin'}, 'bounded hop operation')
    inp = payload['input']
    require(all(type(inp[key]) is str and
                re.fullmatch('[0-9a-f]+', inp[key]) is not None and
                len(inp[key]) <= 262144 for key in ('incoming_hex', 'outgoing_hex'))
            and type(inp['parent_allowed']) is bool and
            type(inp['begin']) is bool and
            all(type(inp[key]) is dict for key in ('parent', 'child')),
            'bounded hop inputs')
    result = subprocess.run([str(adapter)], input=json.dumps(inp).encode(),
                            capture_output=True, timeout=10, check=False)
    require(result.returncode == 0 and not result.stderr and
            len(result.stdout) <= 4096, 'hop core fixture execution')
    output = load(result.stdout)
    require(type(output) is dict and set(output) ==
            {'opened', 'began', 'journal', 'handoffs', 'parent_checks'} and
            all(type(output[key]) is bool for key in
                ('opened', 'began', 'journal')) and
            all(type(output[key]) is int and 0 <= output[key] <= 3
                for key in ('handoffs', 'parent_checks')),
            'hop observation types')
    outcome = {'verdict': 'ACCEPT' if output['opened'] else 'REJECT',
               'output': output,
               'effects': {'handoff': output['handoffs']}}
    validate_outcome(outcome)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': outcome}


def main():
    try:
        adapter = os.environ.get('SAGE_CORE_ADAPTER')
        require(adapter and Path(adapter).is_absolute(),
                'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'hop case exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(adapter)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Current spec Guard hop bridge FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
