"""Audit bounded Go/Rust DID prefix observations without false case promotion."""

import hashlib
import json
from pathlib import Path
import re

from current_spec_catalog import require
from generate_did_prefix_suite import OUTPUT, ROOT, check


REVISIONS = {
    'go': '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
    'rust': 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
}
EXPECTED_STATUSES = ('FAIL', 'PASS', 'PASS', 'UNSUPPORTED',
                     'UNSUPPORTED', 'UNSUPPORTED')


def assess_report(name, report, suite, suite_sha):
    subject = report['subject']
    require(report['schema_version'] == 1 and
            report['protocol_version'] == '0.10.0' and
            report['profile'] == 'primitive-foundation' and
            report['suite_id'] == suite['id'] and
            report['suite_sha256'] == suite_sha and
            report['sources'] == suite['sources'] and
            report['scope'] == ('Only listed primitive cases; no full SAGE, '
                                'state-machine, registry or Execution Guard certification.') and
            subject['revision'] == REVISIONS[name] and
            subject['kind'] == 'external' and
            re.fullmatch('[0-9a-f]{64}', subject['executable_sha256']) is not None and
            len(report['results']) == 6, name + ' report identity')
    statuses = []
    for idx, (case, result) in enumerate(zip(suite['cases'], report['results'])):
        require(result['case_id'] == case['id'] and
                result['operation'] == case['operation'] and
                result['rule_ids'] == case['rule_ids'] and
                result['source_ids'] == case['source_ids'] and
                result['expected'] == case['expected'] and
                result['actual']['schema_version'] == 1 and
                result['actual']['case_id'] == case['id'],
                name + ' case identity')
        status = result['status']
        statuses.append(status)
        actual = result['actual']
        if idx == 0:
            require(status == 'FAIL' and actual['verdict'] == 'REJECT' and
                    actual['output'] == {}, name + ' canonical DID control')
        elif idx in (1, 2):
            require(status == 'PASS' and actual['verdict'] == 'REJECT' and
                    actual['output'] == {}, name + ' mixed-case DID')
        else:
            require(status == 'UNSUPPORTED' and
                    actual['verdict'] == 'UNSUPPORTED' and
                    actual['output'] == {}, name + ' DID URL support')
    require(tuple(statuses) == EXPECTED_STATUSES and
            report['counts'] == {'PASS': 2, 'FAIL': 1,
                                 'UNSUPPORTED': 3, 'NOT_RUN': 0} and
            report['status'] == 'FAIL', name + ' report conclusion')
    return report['counts']


def assess(root=ROOT):
    check(root)
    raw = (root / OUTPUT).read_bytes()
    suite = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    return {name: assess_report(name, json.loads((root / 'docs/evidence' /
            ('did-prefix-' + name + '.json')).read_bytes()), suite, digest)
            for name in REVISIONS}


if __name__ == '__main__':
    print(json.dumps(assess(), sort_keys=True))
