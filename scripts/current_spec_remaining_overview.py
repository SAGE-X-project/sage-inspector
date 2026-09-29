"""Bounded independent review decisions for overview cases."""

IDS = (
    'OVERVIEW-01-P', 'OVERVIEW-01-N01',
    'OVERVIEW-02-P', 'OVERVIEW-02-N01',
    'OVERVIEW-03-P', 'OVERVIEW-03-N01',
    'OVERVIEW-03-N02', 'OVERVIEW-03-N03',
    'OVERVIEW-04-P', 'OVERVIEW-04-N01',
)


def sample(ident):
    if ident.startswith('OVERVIEW-01'):
        return {'grammar_accepted': True,
                'semantic_accepted': ident.endswith('-P'),
                'final_accepted': ident.endswith('-P')}
    if ident.startswith('OVERVIEW-02'):
        negative = ident.endswith('-N01')
        return {'dependency_revision_matches': True,
                'historical_vectors_promoted': 1 if negative else 0,
                'new_conformance_advertised': negative}
    if ident.startswith('OVERVIEW-03'):
        result = {'outer_version': '0.10.0', 'inner_version': '0.10.0',
                  'profile_version': '0.10.0',
                  'selected_version': '0.10.0',
                  'fallback_used': False}
        if ident.endswith('-N01'):
            result['inner_version'] = None
        elif ident.endswith('-N02'):
            result['profile_version'] = '0.9.0'
        elif ident.endswith('-N03'):
            result['outer_version'] = '0.11.0'
            result['fallback_used'] = True
        return result
    return {'normative_decision_source':
            'text' if ident.endswith('-P') else 'go_implementation',
            'text_gap_filled_by_code': not ident.endswith('-P')}


def check(ident, evidence):
    if ident not in IDS or type(evidence) is not dict or \
            set(evidence) != set(sample(ident)):
        return False
    if ident.startswith('OVERVIEW-01'):
        if any(type(evidence[key]) is not bool for key in evidence):
            return False
        accepted = evidence['grammar_accepted'] and \
            evidence['semantic_accepted']
        return (evidence['grammar_accepted'] is True and
                evidence['semantic_accepted'] is ident.endswith('-P') and
                evidence['final_accepted'] is accepted)
    if ident.startswith('OVERVIEW-02'):
        if type(evidence['dependency_revision_matches']) is not bool or \
                type(evidence['historical_vectors_promoted']) is not int or \
                type(evidence['new_conformance_advertised']) is not bool:
            return False
        invalid_claim = (evidence['historical_vectors_promoted'] > 0 and
                         evidence['new_conformance_advertised'])
        return (evidence['dependency_revision_matches'] is True and
                invalid_claim is ident.endswith('-N01'))
    if ident.startswith('OVERVIEW-03'):
        if any(evidence[key] is not None and
               (type(evidence[key]) is not str or
                len(evidence[key]) > 32)
               for key in ('outer_version', 'inner_version',
                           'profile_version', 'selected_version')) or \
                type(evidence['fallback_used']) is not bool:
            return False
        versions = [evidence[key] for key in
                    ('outer_version', 'inner_version',
                     'profile_version', 'selected_version')]
        if ident.endswith('-P'):
            return versions == ['0.10.0'] * 4 and \
                evidence['fallback_used'] is False
        if ident.endswith('-N01'):
            return versions.count(None) == 1 and \
                all(value is None or value == '0.10.0'
                    for value in versions) and \
                evidence['fallback_used'] is False
        if ident.endswith('-N02'):
            return (None not in versions and len(set(versions)) > 1 and
                    evidence['fallback_used'] is False)
        return (None not in versions and len(set(versions)) > 1 and
                evidence['fallback_used'] is True and
                evidence['selected_version'] == '0.10.0')
    return (evidence['normative_decision_source'] ==
            ('text' if ident.endswith('-P') else 'go_implementation') and
            evidence['text_gap_filled_by_code'] is not ident.endswith('-P'))
