"""Assess revision-bound case observations without inheriting historical PASSes."""

import argparse
import collections
import json
from pathlib import Path
import re
import sys

from current_spec_catalog import ROOT, catalog, index, load, require, sha


STATUSES = ('PASS', 'FAIL', 'UNSUPPORTED', 'PARTIAL', 'NOT_RUN')


def same(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == \
           json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def safe_file(root, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and '..' not in Path(relative).parts and '\\' not in relative,
            'unsafe evidence path')
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(),
            'evidence path escape or symlink')
    raw = path.read_bytes()
    require(len(raw) <= 16 * 1024 * 1024, 'evidence file too large')
    return raw


def key(row):
    return row['id'], row['track']


def validate_outcome(value, expected=False):
    require(type(value) is dict and type(value.get('verdict')) is str,
            'invalid typed outcome')
    if value['verdict'] == 'UNSUPPORTED' and not expected:
        require(set(value) == {'verdict', 'reason'} and type(value['reason']) is str
                and value['reason'], 'unsupported outcome needs a reason')
        return
    require(value['verdict'] in ('ACCEPT', 'REJECT') and
            set(value) == {'verdict', 'output', 'effects'} and
            type(value['output']) is dict and type(value['effects']) is dict
            and all(type(count) is int and 0 <= count < 2**64
                    for count in value['effects'].values()), 'invalid typed outcome fields')


def validate_subject(subject):
    require(type(subject) is dict and set(subject) == {'repository', 'revision',
            'executable_sha256'}, 'subject identity fields')
    require(type(subject['repository']) is str and subject['repository'], 'subject repository')
    require(type(subject['revision']) is str and
            re.fullmatch('[0-9a-f]{40}', subject['revision']) is not None,
            'subject revision')
    require(type(subject['executable_sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', subject['executable_sha256']) is not None,
            'subject executable hash')


def load_bindings(root, spec_revision, mapped, children,
                  base_relative='verification/0.10.0/current-spec',
                  fixture_prefix='vectors/0.10.0/current-spec/'):
    base = root / base_relative
    contract = load((base / 'bindings.json').read_bytes())
    require(type(contract) is dict and set(contract) == {'schema_version',
            'spec_revision', 'bindings'} and contract['schema_version'] == 1
            and contract['spec_revision'] == spec_revision, 'binding contract identity')
    result = {}
    require(type(contract['bindings']) is list, 'binding rows')
    for row in contract['bindings']:
        require(type(row) is dict and set(row) == {'id', 'track', 'fixture',
                'fixture_sha256', 'coverage'}, 'binding fields')
        ident, track = key(row)
        require(type(ident) is str and type(track) is str, 'binding identity types')
        require((ident in mapped and track in mapped[ident]['verification_tracks']) or
                (ident in children and track == 'runtime'),
                'binding has unknown case or track: ' + ident)
        require((ident, track) not in result, 'duplicate binding: ' + ident + '/' + track)
        require(row['coverage'] in ('complete', 'partial'), 'binding coverage')
        require(type(row['fixture']) is str and row['fixture'].startswith(
            fixture_prefix), 'fixture outside selected spec vectors')
        raw = safe_file(root, row['fixture'])
        require(sha(raw) == row['fixture_sha256'], 'fixture hash: ' + ident)
        fixture = load(raw)
        require(type(fixture) is dict and set(fixture) == {'schema_version',
                'spec_revision', 'id', 'track', 'input', 'expected'}, 'fixture fields')
        require(fixture['schema_version'] == 1 and fixture['spec_revision'] == spec_revision
                and (fixture['id'], fixture['track']) == (ident, track),
                'fixture identity: ' + ident)
        require(type(fixture['input']) is dict, 'fixture input: ' + ident)
        validate_outcome(fixture['expected'], expected=True)
        result[(ident, track)] = (row, fixture)
    return result


def load_observations(evidence_root, manifest, spec_revision, bindings):
    require(type(manifest) is dict and set(manifest) == {'schema_version',
            'spec_revision', 'subject', 'runner_revision', 'runner_sha256',
            'adapter_sha256',
            'observations'}
            and manifest['schema_version'] == 1 and
            manifest['spec_revision'] == spec_revision, 'observation manifest identity')
    validate_subject(manifest['subject'])
    require(type(manifest['runner_revision']) is str and
            re.fullmatch('[0-9a-f]{40}', manifest['runner_revision']) is not None,
            'runner revision')
    require(type(manifest['adapter_sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', manifest['adapter_sha256']) is not None,
            'adapter executable hash')
    require(type(manifest['runner_sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', manifest['runner_sha256']) is not None,
            'runner source hash')
    require(type(manifest['observations']) is list, 'observation list')
    result = {}
    for row in manifest['observations']:
        require(type(row) is dict and set(row) == {'id', 'track', 'path', 'sha256'},
                'observation row fields')
        ident = key(row)
        require(ident in bindings and ident not in result, 'unbound or duplicate observation')
        raw = safe_file(evidence_root, row['path'])
        require(sha(raw) == row['sha256'], 'observation hash: ' + row['id'])
        actual = load(raw)
        require(type(actual) is dict and set(actual) == {'schema_version',
                'spec_revision', 'id', 'track', 'fixture_sha256', 'input_sha256',
                'subject', 'actual', 'environment'}, 'observation fields')
        binding, fixture = bindings[ident]
        require(actual['schema_version'] == 1 and actual['spec_revision'] == spec_revision
                and (actual['id'], actual['track']) == ident, 'observation identity')
        require(actual['fixture_sha256'] == binding['fixture_sha256'] and
                actual['input_sha256'] == sha(json.dumps(
                    fixture['input'], sort_keys=True, separators=(',', ':'),
                    allow_nan=False).encode()), 'observation fixture/input identity')
        require(same(actual['subject'], manifest['subject']) and
                type(actual['environment']) is str and actual['environment'],
                'observation subject/environment identity')
        validate_outcome(actual['actual'])
        result[ident] = actual['actual']
    return result


def track_status(binding, observation):
    if binding is None or observation is None:
        return 'NOT_RUN'
    row, fixture = binding
    if observation['verdict'] == 'UNSUPPORTED':
        return 'UNSUPPORTED'
    if not same(observation, fixture['expected']):
        return 'FAIL'
    return 'PASS' if row['coverage'] == 'complete' else 'PARTIAL'


def aggregate(statuses):
    if 'FAIL' in statuses:
        return 'FAIL'
    if 'UNSUPPORTED' in statuses:
        return 'UNSUPPORTED'
    if all(status == 'PASS' for status in statuses):
        return 'PASS'
    if any(status in ('PASS', 'PARTIAL') for status in statuses):
        return 'PARTIAL'
    return 'NOT_RUN'


def assess(root=ROOT, evidence_root=None,
           base_relative='verification/0.10.0/current-spec',
           fixture_prefix='vectors/0.10.0/current-spec/',
           kind='current-spec-case-evidence'):
    manifest, trace, mapped = catalog(root, base_relative=base_relative)
    children = index(trace['mandatory_subscenarios'], 'mandatory subscenario')
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children,
                             base_relative, fixture_prefix)
    if evidence_root is None:
        observations, subject = {}, None
    else:
        evidence_manifest = load((evidence_root / 'manifest.json').read_bytes())
        observations = load_observations(evidence_root, evidence_manifest,
                                         manifest['spec_revision'], bindings)
        subject = evidence_manifest['subject']
    child_rows = []
    for child in trace['mandatory_subscenarios']:
        ident = (child['id'], 'runtime')
        child_rows.append({'id': child['id'], 'parent_case': child['parent_case'],
                           'status': track_status(bindings.get(ident), observations.get(ident))})
    by_parent = collections.defaultdict(list)
    for row in child_rows:
        by_parent[row['parent_case']].append(row['status'])
    rows = []
    for case in trace['cases']:
        cid = case['id']
        tracks = {track: track_status(bindings.get((cid, track)),
                                      observations.get((cid, track)))
                  for track in mapped[cid]['verification_tracks']}
        state = aggregate(list(tracks.values()) + by_parent[cid])
        rows.append({'id': cid, 'rule_id': case['rule_id'],
                     'tracks': tracks, 'status': state})
    counts = {state: sum(row['status'] == state for row in rows) for state in STATUSES}
    return {'schema_version': 1, 'kind': kind,
            'spec_revision': manifest['spec_revision'], 'subject': subject,
            'status': 'EVIDENCE_CHECKED' if evidence_root is not None else 'INVENTORY_ONLY',
            'conformance': 'NOT_ESTABLISHED', 'counts': counts,
            'mandatory_subscenarios': child_rows, 'cases': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path,
                        help='Directory with manifest.json and hashed observations')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess(evidence_root=args.evidence)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print('Current spec evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Current spec case results: ' + str(report['counts']) +
          '; conformance NOT_ESTABLISHED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
