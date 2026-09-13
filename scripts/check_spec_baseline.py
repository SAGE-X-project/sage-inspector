"""Validate the pinned INS-01 inventory. No network or third-party dependencies."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check(root, spec=None):
    base = root / 'verification/0.10.0'
    lock = json.loads((base / 'snapshot.json').read_text())
    for entry in lock['files']:
        archived = base / 'snapshot' / entry['path']
        assert digest(archived) == entry['sha256'], f"snapshot changed: {entry['path']}"
        if spec:
            assert digest(spec / entry['path']) == entry['sha256'], f"source drift: {entry['path']}"
    assert digest(root / lock['foundation']['path']) == lock['foundation']['sha256'], 'foundation drift'
    trace = json.loads((base / 'snapshot/verification/traceability.json').read_text())
    matrix = json.loads((base / 'case-map.json').read_text())
    suite = json.loads((root / lock['foundation']['path']).read_text())
    def index(items):
        result = {x['id']: x for x in items}
        assert len(result) == len(items), 'duplicate ID'
        return result
    cases, rules, reqs = (index(trace[k]) for k in ('cases', 'rules', 'requirements'))
    mapped, vectors = index(matrix['cases']), index(matrix['vectors'])
    assert set(mapped) == set(cases) and len(cases) == 386
    assert set(vectors) == set(index(suite['cases'])) and len(vectors) == 26
    for rid, rule in rules.items():
        assert {c['id'] for c in cases.values() if c['rule_id'] == rid} == set(rule['case_ids'])
        assert all(q in reqs and rid in reqs[q]['rule_ids'] for q in rule['requirements'])
    for q, req in reqs.items():
        assert all(q in rules[r]['requirements'] for r in req['rule_ids'])
    for cid, case in cases.items():
        row = mapped[cid]
        assert row['rule_id'] == case['rule_id'] and row['source_mode'] == case['mode']
        assert row['evidence_status'] == 'NOT_RUN'
        assert row['verification_tracks'] and set(row['verification_tracks']) <= {'runtime', 'document_review', 'deployment_review'}
        expected = sorted(v['id'] for v in vectors.values() if cid in v['partial_case_ids'])
        assert row['partial_vector_ids'] == expected
    for vector in vectors.values():
        assert set(vector['related_rule_ids']) <= set(rules)
        assert set(vector['partial_case_ids']) <= set(cases)
        assert vector['relationship'] in ('partial_scenario', 'primitive_prerequisite_only')
        assert vector['limitation']
    print(f"Verified {len(reqs)} requirements, {len(rules)} rules, {len(cases)} NOT_RUN cases, {len(vectors)} vectors; hashes intact")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--spec', type=Path, help='Also detect drift against the current source checkout')
    args = parser.parse_args()
    check(args.root, args.spec)
