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
    core_request = {'schema_version': 1, 'protocol_version': '0.10.0',
                    'profile': 'primitive-foundation', 'case_id': ident,
                    'operation': inp['operation'], 'input': inp['input']}
    proc = subprocess.run([str(adapter)], input=json.dumps(core_request,
                           separators=(',', ':')).encode(), capture_output=True,
                          timeout=10, check=False)
    require(proc.returncode == 0 and len(proc.stdout) <= 1024 * 1024 and
            len(proc.stderr) <= 1024 * 1024, 'core adapter failed or exceeded bound')
    response = load(proc.stdout)
    require(type(response) is dict and set(response) == {'schema_version',
            'case_id', 'verdict', 'output'} and response['schema_version'] == 1
            and response['case_id'] == ident and type(response['output']) is dict,
            'core adapter response identity')
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
