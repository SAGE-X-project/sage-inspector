#!/usr/bin/env python3
"""Translate current case inputs to the existing bounded core primitive adapter."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from current_spec_catalog import catalog, load, require
from current_spec_evidence import validate_outcome


def invoke_core(adapter, ident, operation, inp):
    core_request = {'schema_version': 1, 'protocol_version': '0.10.0',
                    'profile': 'primitive-foundation', 'case_id': ident,
                    'operation': operation, 'input': inp}
    proc = subprocess.run([str(adapter)], input=json.dumps(core_request,
                           separators=(',', ':')).encode(), capture_output=True,
                          timeout=10, check=False)
    require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024 and
            len(proc.stderr) <= 1024 * 1024, 'core adapter failed or exceeded bound')
    response = load(proc.stdout)
    require(type(response) is dict and set(response) == {'schema_version',
            'case_id', 'verdict', 'output'} and response['schema_version'] == 1
            and response['case_id'] == ident and
            response['verdict'] in ('ACCEPT', 'REJECT', 'UNSUPPORTED') and
            type(response['output']) is dict,
            'core adapter response identity')
    return response


def observe(raw, adapter):
    request = load(raw)
    spec_revision = catalog()[0]['spec_revision']
    require(type(request) is dict and set(request) == {'schema_version',
            'spec_revision', 'id', 'track', 'input'} and
            request['schema_version'] == 1 and request['track'] == 'runtime'
            and request['spec_revision'] == spec_revision,
            'case request identity')
    ident = request['id']
    require(type(ident) is str and re.fullmatch('[A-Za-z0-9-]+', ident) is not None,
            'case ID')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'input'} and
            type(inp['operation']) is str and
            re.fullmatch('[A-Za-z0-9_.-]+', inp['operation']) is not None and
            type(inp['input']) is dict, 'primitive input')
    require(adapter.is_file() and not adapter.is_symlink(), 'core adapter path')
    if inp['operation'] == 'http.msg01.primitives':
        fields = inp['input']
        require(set(fields) == {'request_hex', 'response_hex', 'public_key_hex',
                                'body_repeat'} and
                all(type(fields[name]) is str for name in
                    ('request_hex', 'response_hex', 'public_key_hex')) and
                type(fields['body_repeat']) is int and fields['body_repeat'] == 1,
                'HTTP MSG-01 primitive input')
        base = invoke_core(adapter, ident + '-base', 'rfc9421.base', fields)
        digest = invoke_core(adapter, ident + '-digest', 'sage.content-digest', fields)
        if 'UNSUPPORTED' in (base['verdict'], digest['verdict']):
            actual = {'verdict': 'UNSUPPORTED',
                      'reason': 'Core adapter does not expose the HTTP base and digest primitives.'}
        elif base['verdict'] == digest['verdict'] == 'ACCEPT':
            require(set(base['output']) == {'base_hex'} and
                    type(base['output']['base_hex']) is str and
                    digest['output'] == {'valid': True},
                    'HTTP primitive response fields')
            actual = {'verdict': 'ACCEPT',
                      'output': {'base_hex': base['output']['base_hex'],
                                 'digest_valid': True}, 'effects': {}}
        else:
            actual = {'verdict': 'REJECT',
                      'output': {'base_verdict': base['verdict'],
                                 'digest_verdict': digest['verdict']},
                      'effects': {}}
        validate_outcome(actual)
        return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}
    if inp['operation'] == 'jcs.order_pair':
        pair = inp['input']
        require(set(pair) == {'left', 'right'} and
                all(type(pair[name]) is dict and
                    set(pair[name]) == {'document_hex'} and
                    type(pair[name]['document_hex']) is str for name in pair),
                'JCS order pair input')
        left = invoke_core(adapter, ident + '-left',
                           'jcs.canonicalize', pair['left'])
        right = invoke_core(adapter, ident + '-right',
                            'jcs.canonicalize', pair['right'])
        if 'UNSUPPORTED' in (left['verdict'], right['verdict']):
            actual = {'verdict': 'UNSUPPORTED',
                      'reason': 'Core adapter does not expose JCS canonicalization.'}
        else:
            actual = {'verdict': 'ACCEPT' if
                      left['verdict'] == right['verdict'] == 'ACCEPT' else 'REJECT',
                      'output': {'left_verdict': left['verdict'],
                                 'left_output': left['output'],
                                 'right_verdict': right['verdict'],
                                 'right_output': right['output']},
                      'effects': {}}
        validate_outcome(actual)
        return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}
    if inp['operation'] == 'guard.integer_pair':
        pair = inp['input']
        require(set(pair) == {'control', 'candidate'} and
                all(type(pair[name]) is dict for name in pair),
                'guard integer pair input')
        control = invoke_core(adapter, ident + '-control',
                              'sage.guard.intent.verify', pair['control'])
        candidate = invoke_core(adapter, ident + '-candidate',
                                'sage.guard.intent.verify', pair['candidate'])
        if 'UNSUPPORTED' in (control['verdict'], candidate['verdict']):
            actual = {'verdict': 'UNSUPPORTED',
                      'reason': 'Core adapter does not expose Guard intent verification.'}
        else:
            actual = {'verdict': candidate['verdict'],
                      'output': {'control_verdict': control['verdict'],
                                 'control_output': control['output'],
                                 'candidate_output': candidate['output']},
                      'effects': {}}
        validate_outcome(actual)
        return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}
    if inp['operation'] == 'sage.session.sid.project':
        fields = inp['input']
        require(set(fields) == {'seed_hex', 'th_hex'} and
                all(type(fields[name]) is str and len(fields[name]) == 64 and
                    re.fullmatch('[0-9a-f]{64}', fields[name]) is not None
                    for name in fields), 'session ID seed and transcript hash')
        results = {}
        for direction in ('c2s', 's2c'):
            core_input = dict(fields, direction=direction,
                              caller_aad_hex='', plaintext={'byte': 0, 'length': 0})
            results[direction] = invoke_core(adapter, ident + '-' + direction,
                                            'sage.session.record010.export', core_input)
        if any(row['verdict'] == 'UNSUPPORTED' for row in results.values()):
            actual = {'verdict': 'UNSUPPORTED',
                      'reason': 'Core adapter does not expose session record export.'}
        elif all(row['verdict'] == 'ACCEPT' for row in results.values()):
            require(all(set(row['output']) == {'session_id', 'record_hex',
                    'record_sha256', 'record_bytes'} and
                    type(row['output']['session_id']) is str and
                    re.fullmatch('[A-Za-z0-9_-]{22}',
                                 row['output']['session_id']) is not None
                    for row in results.values()), 'session ID export fields')
            actual = {'verdict': 'ACCEPT',
                      'output': {'c2s_sid': results['c2s']['output']['session_id'],
                                 's2c_sid': results['s2c']['output']['session_id']},
                      'effects': {}}
        else:
            actual = {'verdict': 'REJECT', 'output': {}, 'effects': {}}
        validate_outcome(actual)
        return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}
    if inp['operation'] == 'sage.session.record.boundary.probe':
        cases = inp['input'].get('cases')
        require(set(inp['input']) == {'cases'} and type(cases) is list and
                len(cases) == 6, 'session record boundary cases')
        opened = {}
        seen = set()
        unsupported = False
        rejected = False
        for case in cases:
            require(type(case) is dict and set(case) == {'id', 'seed_hex',
                    'th_hex', 'direction', 'record_hex', 'caller_aad_hex'} and
                    type(case['id']) is str and
                    re.fullmatch('[a-z0-9-]+', case['id']) is not None and
                    case['id'] not in seen,
                    'session record boundary case identity')
            seen.add(case['id'])
            response = invoke_core(adapter, ident + '-' + case['id'],
                                   'sage.session.record010.open',
                                   {key: value for key, value in case.items()
                                    if key != 'id'})
            if response['verdict'] == 'UNSUPPORTED':
                unsupported = True
            elif response['verdict'] == 'REJECT':
                rejected = True
            else:
                require(set(response['output']) == {'plaintext_hex'} and
                        type(response['output']['plaintext_hex']) is str,
                        'session record boundary plaintext')
                opened[case['id']] = response['output']['plaintext_hex']
        if unsupported:
            actual = {'verdict': 'UNSUPPORTED',
                      'reason': 'Core adapter does not expose session record opening.'}
        elif rejected:
            actual = {'verdict': 'REJECT', 'output': {'opened': opened},
                      'effects': {}}
        else:
            actual = {'verdict': 'ACCEPT', 'output': {'opened': opened},
                      'effects': {}}
        validate_outcome(actual)
        return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}
    response = invoke_core(adapter, ident, inp['operation'], inp['input'])
    if response['verdict'] == 'UNSUPPORTED':
        actual = {'verdict': 'UNSUPPORTED',
                  'reason': 'Core primitive adapter does not expose this operation.'}
    else:
        actual = {'verdict': response['verdict'], 'output': response['output'],
                  'effects': {}}
    validate_outcome(actual)
    return {'schema_version': 1, 'id': ident, 'track': 'runtime', 'actual': actual}


def main():
    try:
        path = os.environ.get('SAGE_CORE_ADAPTER')
        require(path and Path(path).is_absolute(), 'absolute SAGE_CORE_ADAPTER required')
        raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, 'case request too large')
        response = observe(raw, Path(path))
        print(json.dumps(response, separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print('Current spec primitive bridge FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
