#!/usr/bin/env python3
"""Observe guarded RPC route exclusions through an inert local core sink."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome


def route(adapter, configuration, outer_id, version, wire_hex):
    actions = [{'action': 'configure', 'instance': 'old',
                'input': configuration},
               {'action': 'rpc_setup', 'mcp_version': version},
               {'action': 'rpc_dispatch', 'id': outer_id,
                'envelope_hex': wire_hex}]
    wire = ''.join(json.dumps(row, separators=(',', ':')) + '\n'
                   for row in actions).encode()
    require(len(wire) <= 1024 * 1024, 'bounded RPC input')
    with tempfile.TemporaryDirectory(prefix='sage-rpc-route-') as temporary:
        journal = Path(temporary) / 'ledger'
        proc = subprocess.run([str(adapter), str(journal), 'create'],
                              input=wire, capture_output=True, timeout=10,
                              check=False)
        require(proc.returncode == 0 and not proc.stderr and
                len(proc.stdout) <= 1024 * 1024, 'guarded RPC core run')
        rows = [load(line) for line in proc.stdout.splitlines()]
        require(len(rows) == 3 and rows[0]['ok'] is True and
                rows[1]['ok'] is True and journal.is_file() and
                not journal.is_symlink(), 'guarded RPC setup')
        lines = journal.read_bytes().splitlines()
    require(lines and lines[0] == b'sage-execution-ledger|0.10.0' and
            len(lines) <= 4, 'guarded RPC journal')
    states = [load(line)['state'] for line in lines[1:]]
    row = rows[2]
    require(type(row['ok']) is bool and type(row['committed']) is bool and
            type(row['effects']) is list and len(row['effects']) <= 1 and
            type(row['signs']) is int and row['signs'] == 0 and
            row['result_hex'] == '', 'guarded RPC result types')
    return {'accepted': row['ok'], 'committed': row['committed'],
            'effects': len(row['effects']), 'journal_states': states}


def observe(raw, adapter):
    request = load(raw)
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == catalog()[0]['spec_revision'] and
            request['track'] == 'runtime' and
            request['id'] in ('EXEC-08-N04', 'EXEC-08-N05') and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'RPC route case identity')
    payload = request['input']
    require(type(payload) is dict and
            set(payload) == {'operation', 'input'} and
            payload['operation'] == 'sage.guard.rpc.route_pair' and
            type(payload['input']) is dict and
            set(payload['input']) == {'configuration', 'outer_id',
                                      'mcp_version', 'control_wire_hex',
                                      'candidate_wire_hex'}, 'RPC route operation')
    inp = payload['input']
    require(type(inp['configuration']) is dict and
            type(inp['outer_id']) is str and
            inp['mcp_version'] == '2025-06-18' and
            all(type(inp[key]) is str and len(inp[key]) <= 262144 and
                re.fullmatch('[0-9a-f]+', inp[key]) is not None
                for key in ('control_wire_hex', 'candidate_wire_hex')),
            'bounded RPC route pair')
    control = route(adapter, inp['configuration'], inp['outer_id'],
                    inp['mcp_version'], inp['control_wire_hex'])
    candidate = route(adapter, inp['configuration'], inp['outer_id'],
                      inp['mcp_version'], inp['candidate_wire_hex'])
    outcome = {'verdict': 'ACCEPT' if candidate['accepted'] else 'REJECT',
               'output': {'control': control, 'candidate': candidate},
               'effects': {'candidate_dispatch': candidate['effects']}}
    validate_outcome(outcome)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': outcome}


def main():
    try:
        adapter = os.environ.get('SAGE_CORE_ADAPTER')
        require(adapter and Path(adapter).is_absolute(),
                'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'RPC route case exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(adapter)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Current spec Guard RPC route FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
