"""Unit tests of expiry fixtures and Inspector judgment; no core or simulator runs."""
import copy
import hashlib
import json
import unittest

from inspect_session import ROOT, validate_scenario

FIXTURES = ROOT / 'vectors/0.10.0/session-scenarios'


def fixture(name):
    return json.loads((FIXTURES / ('session-' + name + '.json')).read_text())


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


def boundary(kind, offset):
    """Test-local variants preserve frozen inputs; expectations below are explicit."""
    names = {'idle': 'idle-boundary', 'absolute': 'absolute-boundary', 'provisional': 'provisional-deadline'}
    f = fixture(names[kind])
    limits = {'idle': 1199, 'absolute': 3600, 'provisional': 300}
    f['id'] = 'unit-' + kind + '-' + str(offset)
    clock, receive, inspect = f['steps'][-3:]
    clock['input']['monotonic'] = limits[kind] + offset
    if offset == -1:
        # The configured maximum policy permits the valid record before expiry.
        receive['expected'] = dict(verdict='ACCEPT', output=dict(accepted=1, rejected=0, verdicts=['ACCEPT']))
        accepted, seen = {'idle': (2, [0, 1]), 'absolute': (8, list(range(1, 9))), 'provisional': (1, [7])}[kind]
        effects = dict(accepted=accepted, emitted=0, allocated=0, dispatch=accepted,
                       confirmations=1 if kind == 'provisional' else 0, closed=0)
        receive['effects'] = effects
        inspect['expected']['output'] = dict(state='ESTABLISHED', next_send=0, received=seen,
                                            last_activity=limits[kind]-1, keys_available=True)
        inspect['effects'] = copy.deepcopy(effects)
    return f


class SessionExpiryTests(unittest.TestCase):
    def test_frozen_boundary_anchors(self):
        # Literal anchors independently pin the intended configured upper limits.
        for name, before, at, activity, accepted in [
            ('idle-boundary', 599, 1199, 599, 1),
            ('absolute-boundary', 3599, 3600, 3599, 7),
        ]:
            with self.subTest(name=name):
                steps = fixture(name)['steps']
                self.assertEqual(steps[-6]['input'], {'monotonic': before})
                self.assertEqual(steps[-5]['expected']['verdict'], 'ACCEPT')
                self.assertEqual(steps[-3]['input'], {'monotonic': at})
                self.assertEqual(steps[-2]['expected'], {'verdict': 'REJECT', 'output': {}})
                self.assertEqual(steps[-2]['effects']['accepted'], accepted)
                self.assertEqual(steps[-1]['expected']['output']['last_activity'], activity)
                self.assertEqual(steps[-1]['expected']['output']['state'], 'CLOSED')
                self.assertIs(steps[-1]['expected']['output']['keys_available'], False)

    def test_before_at_and_after_expiry(self):
        for kind in ('idle', 'absolute', 'provisional'):
            for offset in (-1, 0, 1):
                with self.subTest(kind=kind, offset=offset):
                    raw, report = synthetic_report(boundary(kind, offset))
                    validate_scenario(raw, report)
                    # A wrong acceptance or premature rejection must not pass.
                    report['steps'][-2]['actual']['verdict'] = 'REJECT' if offset == -1 else 'ACCEPT'
                    with self.assertRaises(ValueError):
                        validate_scenario(raw, report)

    def test_expired_receive_has_no_hidden_effects(self):
        for kind in ('idle', 'absolute', 'provisional'):
            raw, original = synthetic_report(boundary(kind, 0))
            for counter in ('accepted', 'dispatch', 'allocated', 'emitted', 'confirmations', 'closed'):
                with self.subTest(kind=kind, counter=counter):
                    report = copy.deepcopy(original)
                    report['steps'][-2]['actual']['effects'][counter] += 1
                    with self.assertRaises(ValueError): validate_scenario(raw, report)
            for field, value in [('state', 'ESTABLISHED'), ('keys_available', True), ('last_activity', 3601)]:
                report = copy.deepcopy(original)
                report['steps'][-1]['actual']['output'][field] = value
                with self.assertRaises(ValueError): validate_scenario(raw, report)

    def test_invalid_traffic_does_not_refresh_idle_time(self):
        f = fixture('invalid-idle')
        self.assertEqual(f['steps'][1]['input'], {'monotonic': 599})
        self.assertEqual(f['steps'][2]['expected']['verdict'], 'REJECT')
        self.assertEqual(f['steps'][3]['expected']['output']['last_activity'], 0)
        self.assertEqual(f['steps'][4]['input'], {'monotonic': 600})
        self.assertEqual(f['steps'][5]['expected']['verdict'], 'REJECT')
        raw, report = synthetic_report(f)
        validate_scenario(raw, report)
        report['steps'][3]['actual']['output']['last_activity'] = 599
        with self.assertRaises(ValueError): validate_scenario(raw, report)

    def test_expiry_during_confirmation_and_no_lifetime_reset(self):
        f = fixture('provisional-commit-deadline')
        self.assertEqual(f['steps'][1]['input'], {'monotonic': 299})
        self.assertEqual(f['steps'][2]['input']['commit_monotonic'], 300)
        self.assertEqual(f['steps'][2]['expected']['verdict'], 'REJECT')
        raw, report = synthetic_report(f)
        validate_scenario(raw, report)
        report['steps'][2]['input'].pop('commit_monotonic')
        with self.assertRaises(ValueError): validate_scenario(raw, report)
        f = fixture('provisional-no-clock-reset')
        self.assertEqual(f['steps'][3]['expected']['output']['state'], 'ESTABLISHED')
        self.assertEqual(f['steps'][-3]['input'], {'monotonic': 3600})
        self.assertEqual(f['steps'][-2]['expected']['verdict'], 'REJECT')
        raw, report = synthetic_report(f)
        validate_scenario(raw, report)
        report['steps'][-2]['actual']['verdict'] = 'ACCEPT'
        with self.assertRaises(ValueError): validate_scenario(raw, report)

    def test_boolean_counters_and_clocks_are_not_numbers(self):
        raw, original = synthetic_report(boundary('provisional', 0))
        for kind in ('effects', 'expected-effects', 'clock', 'keys', 'report-schema', 'observation-schema'):
            report = copy.deepcopy(original)
            if kind == 'effects': report['steps'][-2]['actual']['effects']['dispatch'] = False
            if kind == 'expected-effects': report['steps'][-2]['expected_effects']['dispatch'] = False
            if kind == 'clock': report['steps'][0]['input']['created_monotonic'] = False
            if kind == 'keys': report['steps'][-1]['actual']['output']['keys_available'] = 0
            if kind == 'report-schema': report['schema_version'] = 2.0
            if kind == 'observation-schema': report['steps'][-2]['actual']['schema_version'] = 2.0
            with self.subTest(kind=kind), self.assertRaises(ValueError): validate_scenario(raw, report)

    def test_unsupported_clock_stops_remaining_steps(self):
        raw, report = synthetic_report(boundary('idle', 0))
        report['status'] = 'INCOMPLETE'
        step = report['steps'][1]
        step['status'] = 'UNSUPPORTED'
        step['actual'].update(verdict='UNSUPPORTED', output={}, effects={})
        for step in report['steps'][2:]:
            step['status'] = 'NOT_RUN'; step.pop('actual')
        validate_scenario(raw, report)
        report['status'] = 'PASS'
        with self.assertRaises(ValueError): validate_scenario(raw, report)
        report['status'] = 'INCOMPLETE'
        report['steps'][2]['actual'] = {'verdict': 'REJECT'}
        with self.assertRaises(ValueError): validate_scenario(raw, report)

    def test_missing_observation_or_step_never_passes(self):
        raw, original = synthetic_report(boundary('absolute', 1))
        for kind in ('observation', 'step', 'effects'):
            report = copy.deepcopy(original)
            if kind == 'observation': report['steps'][-2].pop('actual')
            if kind == 'step': report['steps'].pop()
            if kind == 'effects': report['steps'][-2]['actual']['effects'] = {}
            with self.subTest(kind=kind), self.assertRaises(ValueError): validate_scenario(raw, report)

if __name__ == '__main__':
    unittest.main()
