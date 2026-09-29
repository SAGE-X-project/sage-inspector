#!/usr/bin/env python3
"""Observe bounded Guard client result consumption with a local core binary."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome
from current_spec_guard_results_bridge import verified_result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run_scenario(adapter, source, scenario):
    config = source['configuration']
    public = source['public_key_hex']
    results = source['results']
    require(type(config) is dict and type(public) is str and
            re.fullmatch('[0-9a-f]{64}', public) is not None and
            type(results) is dict and type(scenario) is dict and
            set(scenario) == {'name', 'steps'} and
            type(scenario['name']) is str and
            type(scenario['steps']) is list and
            1 <= len(scenario['steps']) <= 16, 'bounded client scenario')
    intent_hex = config['envelope_hex']
    intent_sha = sha(bytes.fromhex(intent_hex))
    commands = [{'action': 'open', 'input': config,
                 'public_key_hex': public, 'utc': 1700000000000, 'mono': 0}]
    signed_inputs = []
    for step in scenario['steps']:
        require(type(step) is dict and step.get('action') in
                ('tick', 'begin', 'accept', 'failed', 'set', 'close') and
                'expected' not in step, 'unexpected client action')
        command = step.copy()
        if command['action'] == 'accept':
            name = command.pop('result')
            require(name in results and type(results[name]) is str,
                    'missing signed result input')
            command['envelope_hex'] = results[name]
            signed_inputs.append(results[name])
        commands.append(command)
    wire = ''.join(json.dumps(command, separators=(',', ':')) + '\n'
                   for command in commands).encode()
    require(len(wire) <= 1024 * 1024 and
            all(verified_result(envelope, public, intent_sha)[1]
                for envelope in signed_inputs),
            'signed result input or size')
    with tempfile.TemporaryDirectory(prefix='sage-client-current-') as temporary:
        journal = Path(temporary) / 'journal'
        process = subprocess.run([str(adapter), str(journal), 'create'],
                                 input=wire, capture_output=True, timeout=10,
                                 check=False)
        require(process.returncode == 0 and not process.stderr and
                len(process.stdout) <= 1024 * 1024 and
                journal.is_file() and not journal.is_symlink(),
                'core client fixture failed')
        rows = [load(line) for line in process.stdout.splitlines()]
        raw = journal.read_bytes()
    require(len(rows) == len(commands) and
            raw.startswith(b'sage-guard-client|0.10.0\n') and
            raw.endswith(b'\n') and len(raw) <= 1024 * 1024,
            'client replies or journal framing')
    events = [load(line) for line in
              raw[len(b'sage-guard-client|0.10.0\n'):].splitlines()]
    require(all(type(row) is dict and
                all(type(row.get(key)) is bool for key in
                    ('ok', 'first', 'ignored')) and
                type(row.get('handoffs')) is int and
                type(row.get('status')) is str and
                type(row.get('intent_hex')) is str
                for row in rows) and
            all(type(event) is dict and type(event.get('kind')) is str
                for event in events), 'client reply and journal types')
    delivered = [row for row in rows if row['intent_hex']]
    terminal = [event for event in events if event['kind'] == 'terminal']
    unchanged = all(row['intent_hex'] == intent_hex for row in delivered)
    signed = all(verified_result(event['result_hex'], public, intent_sha)[1]
                 for event in terminal)
    return {'steps': [{key: row[key] for key in
                      ('ok', 'status', 'first', 'ignored', 'handoffs')}
                     for row in rows],
            'journal_kinds': [event['kind'] for event in events],
            'terminal_results': len(terminal),
            'intent_unchanged': unchanged,
            'signed_results_valid': signed}


def observe(raw, adapter):
    request = load(raw)
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id', 'track', 'input'} and
            request['schema_version'] == 1 and request['track'] == 'runtime' and
            request['spec_revision'] == catalog()[0]['spec_revision'] and
            type(request['id']) is str and
            re.fullmatch('[A-Za-z0-9-]+', request['id']) is not None and
            adapter.is_absolute() and adapter.is_file() and
            not adapter.is_symlink(), 'case request and adapter identity')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'input'} and
            inp['operation'] == 'sage.guard.client.sequence' and
            type(inp['input']) is dict and
            set(inp['input']) == {'configuration', 'public_key_hex',
                                  'results', 'scenarios'}, 'client operation')
    source = inp['input']
    scenarios = source['scenarios']
    require(type(scenarios) is list and 1 <= len(scenarios) <= 2 and
            all(type(row) is dict for row in scenarios) and
            len({row.get('name') for row in scenarios}) == len(scenarios),
            'scenario count and identity')
    outcomes = {scenario['name']: run_scenario(adapter, source, scenario)
                for scenario in scenarios}
    outcome = {'verdict': 'ACCEPT', 'output': {'scenarios': outcomes},
               'effects': {'handoff': max(
                   max(step['handoffs'] for step in value['steps'])
                   for value in outcomes.values())}}
    validate_outcome(outcome)
    return {'schema_version': 1, 'id': request['id'], 'track': 'runtime',
            'actual': outcome}


def main():
    try:
        adapter = os.environ.get('SAGE_CORE_ADAPTER')
        require(adapter and Path(adapter).is_absolute(),
                'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'case request exceeds 1 MiB')
        print(json.dumps(observe(raw, Path(adapter)), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError, InvalidSignature,
            subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print('Current spec Guard client bridge FAIL: ' + str(error),
              file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
