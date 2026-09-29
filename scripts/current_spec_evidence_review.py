"""Bounded EVIDENCE-01 reporting and independence review model."""

from current_spec_catalog import require


IDS = ('EVIDENCE-01-P', 'EVIDENCE-01-N01', 'EVIDENCE-01-N02')
TRACKS = ('runtime', 'document_review', 'deployment_review')


def evaluate(ident, track, report):
    require(ident in IDS and track in TRACKS and type(report) is dict and
            set(report) == {'claim', 'executions', 'implementations',
                            'spec_revision'}, 'evidence review fields')
    require(report['claim'] == 'measured_interoperability' and
            type(report['spec_revision']) is str and
            len(report['spec_revision']) == 40 and
            type(report['executions']) is list and
            type(report['implementations']) is list,
            'evidence review values')
    measured = bool(report['executions']) and all(
        type(row) is dict and set(row) == {'input_sha256', 'revision', 'duration_ms'}
        and type(row['input_sha256']) is str and len(row['input_sha256']) == 64
        and type(row['revision']) is str and len(row['revision']) == 40
        and type(row['duration_ms']) is int and row['duration_ms'] >= 0
        for row in report['executions'])
    implementations = report['implementations']
    independent = len(implementations) >= 2 and all(
        type(row) is dict and set(row) == {'repository', 'revision', 'executable_sha256'}
        and type(row['repository']) is str and row['repository']
        and type(row['revision']) is str and len(row['revision']) == 40
        and type(row['executable_sha256']) is str and
        len(row['executable_sha256']) == 64 for row in implementations)
    if independent:
        independent = (len({row['repository'] for row in implementations}) ==
                       len(implementations) and
                       len({row['executable_sha256'] for row in implementations}) ==
                       len(implementations))
    accepted = measured and independent
    reason = ('versioned_distinct_observations' if accepted else
              'missing_measurement' if not measured else
              'same_implementation_not_independent')
    return {'verdict': 'ACCEPT' if accepted else 'REJECT',
            'output': {'accepted': accepted, 'reason': reason,
                       'review_track': track}, 'effects': {}}
