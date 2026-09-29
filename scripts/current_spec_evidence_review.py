"""Bounded EVIDENCE-01 reporting and independence review model."""

from current_spec_catalog import require


IDS = ('EVIDENCE-01-P', 'EVIDENCE-01-N01', 'EVIDENCE-01-N02')
TRACKS = ('runtime', 'document_review', 'deployment_review')


def hex_string(value, length):
    return type(value) is str and len(value) == length and \
        all(char in '0123456789abcdef' for char in value)


def evaluate(ident, track, report, expected_revision):
    require(ident in IDS and track in TRACKS and type(report) is dict and
            set(report) == {'claim', 'executions', 'implementations',
                            'spec_revision'}, 'evidence review fields')
    require(report['claim'] == 'measured_interoperability' and
            hex_string(expected_revision, 40) and
            type(report['executions']) is list and
            len(report['executions']) <= 64 and
            type(report['implementations']) is list and
            len(report['implementations']) <= 16,
            'evidence review values')
    revision_matches = report['spec_revision'] == expected_revision
    measured = bool(report['executions']) and all(
        type(row) is dict and set(row) == {'input_sha256', 'revision', 'duration_ms'}
        and hex_string(row['input_sha256'], 64)
        and hex_string(row['revision'], 40)
        and type(row['duration_ms']) is int and 0 <= row['duration_ms'] < 2**64
        for row in report['executions'])
    implementations = report['implementations']
    independent = len(implementations) >= 2 and all(
        type(row) is dict and set(row) == {'repository', 'revision', 'executable_sha256'}
        and type(row['repository']) is str and row['repository']
        and hex_string(row['revision'], 40)
        and hex_string(row['executable_sha256'], 64)
        for row in implementations)
    if independent:
        independent = (len({row['repository'] for row in implementations}) ==
                       len(implementations) and
                       len({row['executable_sha256'] for row in implementations}) ==
                       len(implementations))
    linked = measured and independent and all(
        row['revision'] in {item['revision'] for item in implementations}
        for row in report['executions'])
    accepted = revision_matches and measured and independent and linked
    reason = ('versioned_distinct_observations' if accepted else
              'wrong_spec_revision' if not revision_matches else
              'missing_measurement' if not measured else
              'same_implementation_not_independent' if not independent else
              'unattributed_execution')
    return {'verdict': 'ACCEPT' if accepted else 'REJECT',
            'output': {'accepted': accepted, 'reason': reason,
                       'review_track': track}, 'effects': {}}
