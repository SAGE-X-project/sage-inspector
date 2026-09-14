"""Scripted observations for Inspector tests, never real core evidence."""
import copy
import hashlib
import json


def synthetic_report(f):
    # Scripted observations test the report validator, not a session implementation.
    raw = json.dumps(f).encode()
    report = dict(schema_version=2, protocol_version='0.10.0', profile='stateful-scenario',
                  case_id=f['id'], fixture_sha256=hashlib.sha256(raw).hexdigest(),
                  subject={'name': 'unit-test-scripted-observations', 'kind': 'test-double'},
                  status='PASS', steps=[])
    for step in f['steps']:
        report['steps'].append(dict(step_id=step['id'], input=copy.deepcopy(step['input']),
                                   expected=copy.deepcopy(step['expected']),
                                   expected_effects=copy.deepcopy(step['effects']), status='PASS',
                                   actual=dict(schema_version=2, case_id=f['id'], step_id=step['id'],
                                               **copy.deepcopy(step['expected']), effects=copy.deepcopy(step['effects']))))
    return raw, report
