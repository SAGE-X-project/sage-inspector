"""Validate the Go review against adopted mandatory MCP child schedules."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/go-normative-review-contract.json'
BASELINE = ROOT / 'verification/0.10.0/normative-baseline-lock.json'
STATUSES = {'DIRECT', 'PARTIAL', 'MISSING'}


def require(value, message):
    if not value:
        raise ValueError(message)


def load(raw):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError('non-finite number')))


def git_head(path):
    return subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=path, text=True, timeout=10).strip()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def test_inventory(go_root):
    found = {}
    for path in (go_root / 'pkg/agent').rglob('*_test.go'):
        text = path.read_text()
        for name in re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)', text, re.M):
            found.setdefault(name, []).append(str(path.relative_to(go_root)))
    return found


def validate_contract(value):
    require(set(value) == {'schema_version','protocol_version','kind','spec_revision',
                           'go_revision','review_status','counts','children','conformance'},
            'contract fields')
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0',
            'contract version')
    require(value['kind'] == 'go-normative-implementation-review', 'contract kind')
    require(value['review_status'] == 'INCOMPLETE', 'review status promotion')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    baseline = load(BASELINE.read_text())
    require(value['spec_revision'] == baseline['spec']['revision'], 'spec revision')
    require(value['go_revision'] == baseline['cores']['go']['revision'], 'Go revision')
    rows = value['children']
    require(type(rows) is list and len(rows) == 26, 'child count')
    require(len({row.get('id') for row in rows}) == 26, 'child identity uniqueness')
    derived = {status:0 for status in STATUSES}
    for row in rows:
        require(set(row) == {'id','status','tests','observation','required'},
                'child fields')
        require(row['status'] in STATUSES, 'child status')
        require(type(row['tests']) is list and len(set(row['tests'])) == len(row['tests']),
                'test list')
        require((row['status'] == 'MISSING') == (not row['tests']),
                'missing evidence classification')
        require(len(row['observation']) >= 40 and len(row['required']) >= 30,
                'review explanation')
        derived[row['status']] += 1
    require(value['counts'] == derived == {'DIRECT':16,'PARTIAL':5,'MISSING':5},
            'review counts')
    return value


def validate_spec(value, spec_root, revision_reader=git_head):
    require(revision_reader(spec_root) == value['spec_revision'], 'checked spec revision')
    trace = load((spec_root / 'verification/traceability.json').read_text())
    require(trace['binding_adoption']['status'] == 'ADOPTED_NORMATIVE_DESIGN',
            'binding adoption status')
    require(trace['binding_adoption']['parent_cases'] == 71 and
            trace['binding_adoption']['mandatory_child_assertions'] == 26,
            'binding adoption counts')
    expected = {row['id'] for row in trace['mandatory_subscenarios']}
    actual = {row['id'] for row in value['children']}
    require(actual == expected, 'mandatory child inventory')
    return trace


def validate_go(value, go_root, revision_reader=git_head):
    require(revision_reader(go_root) == value['go_revision'], 'checked Go revision')
    inventory = test_inventory(go_root)
    for row in value['children']:
        for name in row['tests']:
            require(name in inventory, 'missing Go test definition: ' + name)
    return inventory


def inspect(spec_root, go_root):
    raw = CONTRACT.read_bytes()
    value = validate_contract(load(raw.decode()))
    validate_spec(value, spec_root)
    inventory = validate_go(value, go_root)
    return {
        'schema_version': 1,
        'protocol_version': '0.10.0',
        'kind': 'go-normative-implementation-review-report',
        'status': value['review_status'],
        'spec_revision': value['spec_revision'],
        'go_revision': value['go_revision'],
        'counts': value['counts'],
        'mapped_go_tests': len({name for row in value['children'] for name in row['tests']}),
        'discovered_go_tests': len(inventory),
        'next_step': 'close PARTIAL and MISSING Go schedules before Rust review',
        'conformance': 'NOT_ESTABLISHED',
        'contract_sha256': sha(raw)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and not output.is_relative_to(ROOT),
                'new external output required')
        report = inspect(args.spec_root.resolve(), args.go_root.resolve())
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Go normative review FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Go normative review checked: 16 DIRECT, 5 PARTIAL, 5 MISSING; '
          'conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
