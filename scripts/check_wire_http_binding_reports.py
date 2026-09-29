"""Audit preserved Go/Rust observations without promoting boundary support."""

import hashlib
import json
import re
from pathlib import Path

from generate_wire_http_binding_suite import OUTPUT, ROOT, check


REVISIONS = {
    'go': '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
    'rust': 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
}
EXPECTED_STATUSES = {
    'go': ('FAIL', 'FAIL', 'PASS', 'PASS', 'UNSUPPORTED', 'UNSUPPORTED'),
    'rust': ('PASS', 'PASS', 'PASS', 'PASS', 'UNSUPPORTED', 'UNSUPPORTED'),
}


def require(condition, label):
    if not condition:
        raise ValueError(label)


def assess_report(name, report, suite, suite_sha):
    cases = suite['cases']
    subject = report['subject']
    require(report['schema_version'] == 1 and
            report['protocol_version'] == '0.10.0' and
            report['profile'] == 'primitive-foundation' and
            report['suite_id'] == suite['id'] and
            report['suite_sha256'] == suite_sha and
            subject['revision'] == REVISIONS[name] and
            subject['kind'] == 'external' and
            re.fullmatch('[0-9a-f]{64}', subject['executable_sha256']) is not None and
            len(report['results']) == len(cases), name + ' report identity')
    statuses = []
    for case, result in zip(cases, report['results']):
        actual = result['actual']
        require(result['case_id'] == case['id'] and
                result['operation'] == case['operation'] and
                result['rule_ids'] == case['rule_ids'] and
                result['expected'] == case['expected'] and
                actual['schema_version'] == 1 and
                actual['case_id'] == case['id'], name + ' case identity')
        status = result['status']
        statuses.append(status)
        if status == 'UNSUPPORTED':
            require(case['operation'] == 'sage.http.verify' and
                    actual['verdict'] == 'UNSUPPORTED' and
                    actual['output'] == {}, name + ' boundary support')
        elif status == 'PASS':
            require(actual['verdict'] == case['expected']['verdict'] and
                    actual['output'] == case['expected']['output'],
                    name + ' passing primitive')
        elif status == 'FAIL':
            require(name == 'go' and case['operation'] == 'rfc9421.base' and
                    actual['verdict'] == 'ACCEPT' and
                    set(actual['output']) == {'base_hex'},
                    name + ' failure classification')
            expected = bytes.fromhex(case['expected']['output']['base_hex'])
            observed = bytes.fromhex(actual['output']['base_hex'])
            require(observed == expected.replace(b';tag="sage-0.10.0"', b'') and
                    observed != expected, 'Go dropped required RFC 9421 tag')
        else:
            raise ValueError(name + ' unexpected status')
    require(tuple(statuses) == EXPECTED_STATUSES[name], name + ' status sequence')
    counts = {status: statuses.count(status)
              for status in ('PASS', 'FAIL', 'UNSUPPORTED', 'NOT_RUN')}
    require(report['counts'] == counts and
            report['status'] == ('FAIL' if name == 'go' else 'INCOMPLETE'),
            name + ' report conclusion')
    return counts


def assess(root=ROOT):
    check(root)
    suite_raw = (root / OUTPUT.relative_to(ROOT)).read_bytes()
    suite = json.loads(suite_raw)
    suite_sha = hashlib.sha256(suite_raw).hexdigest()
    result = {}
    for name in REVISIONS:
        path = root / 'docs/evidence' / ('wire-http-binding-' + name + '.json')
        result[name] = assess_report(name, json.loads(path.read_bytes()),
                                     suite, suite_sha)
    return result


if __name__ == '__main__':
    print(json.dumps(assess(), sort_keys=True))
