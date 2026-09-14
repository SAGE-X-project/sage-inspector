"""Recovery fixture and judgment unit tests; no actual crash or host action."""
import copy
import json
import unittest
from inspect_session import ROOT, validate_scenario as session_validate
from inspect_guard import validate_scenario as guard_validate
from scenario_test_support import synthetic_report

NAMES = ('session-restart', 'guard-crash-reserved', 'guard-crash-executing',
         'guard-terminal-persistence-failure', 'guard-lost-ledger', 'guard-scope-recovery')


def load(name):
    group = name.split('-')[0]
    return json.loads((ROOT/'vectors/0.10.0'/ (group+'-scenarios')/(name+'.json')).read_text())


def validator(name):
    return session_validate if name.startswith('session-') else guard_validate


class RecoveryTests(unittest.TestCase):
    def test_session_stays_closed_without_redispatch(self):
        f = load('session-restart'); steps = f['steps']
        self.assertEqual(steps[3]['input']['action'], 'restart')
        for i in (4, 6, 8):
            self.assertEqual(steps[i]['expected']['output']['state'], 'CLOSED')
            self.assertIs(steps[i]['expected']['output']['keys_available'], False)
        for i in (5, 7):
            self.assertEqual(steps[i]['expected']['verdict'], 'REJECT')
            self.assertEqual(steps[i]['effects']['dispatch'], 1)
        raw, report = synthetic_report(f); session_validate(raw, report)
        report['steps'][4]['actual']['output']['state'] = 'ESTABLISHED'
        with self.assertRaises(ValueError): session_validate(raw, report)

    def test_unresolved_guard_work_remains_unknown(self):
        for name, dispatch in [('guard-crash-reserved', 0), ('guard-crash-executing', 1)]:
            f = load(name); crash = next(i for i,s in enumerate(f['steps']) if s['input'].get('action') == 'crash')
            for s in f['steps'][crash+1:]:
                self.assertEqual(s['effects']['dispatch'], dispatch)
                if s['input'].get('action') == 'inspect':
                    self.assertEqual({e['state'] for e in s['expected']['output']['entries'].values()}, {'UNKNOWN'})
                if s['input'].get('action') in ('dispatch', 'complete'):
                    self.assertEqual(s['expected']['verdict'], 'REJECT')
            raw, report = synthetic_report(f); guard_validate(raw, report)
            report['steps'][crash+1]['actual']['effects']['dispatch'] += 1
            with self.assertRaises(ValueError): guard_validate(raw, report)

    def test_storage_failure_cannot_produce_terminal_success(self):
        f = load('guard-terminal-persistence-failure')
        complete = next(i for i,s in enumerate(f['steps']) if s['input'].get('action') == 'complete')
        self.assertEqual(f['steps'][complete]['expected']['verdict'], 'REJECT')
        self.assertEqual(f['steps'][complete]['effects'], f['steps'][complete-1]['effects'])
        raw, report = synthetic_report(f); guard_validate(raw, report)
        report['steps'][complete]['actual']['verdict'] = 'ACCEPT'
        with self.assertRaises(ValueError): guard_validate(raw, report)

    def test_lost_ledger_and_partial_recovery_fail_closed(self):
        f = load('guard-lost-ledger')
        loss = next(i for i,s in enumerate(f['steps']) if s['input'].get('action') == 'lose-ledger')
        for s in f['steps'][loss+1:]:
            if s['input'].get('action') == 'inspect': self.assertIs(s['expected']['output']['ledger_intact'], False)
            if s['input'].get('action') in ('submit','recover'): self.assertEqual(s['expected']['verdict'], 'REJECT')
        f = load('guard-scope-recovery')
        self.assertEqual([s['expected']['verdict'] for s in f['steps'] if s['input'].get('action') == 'recover'], ['REJECT','ACCEPT','REJECT'])
        self.assertEqual([s['expected']['verdict'] for s in f['steps'] if s['input'].get('action') == 'submit'], ['REJECT','ACCEPT'])
        self.assertEqual(f['steps'][-1]['effects']['dispatch'], 1)
        self.assertNotEqual(f['steps'][2]['expected']['output']['approved_policy'], f['steps'][6]['expected']['output']['approved_policy'])
        raw, report = synthetic_report(f); guard_validate(raw, report)
        report['steps'][7]['actual']['verdict'] = 'ACCEPT'
        with self.assertRaises(ValueError): guard_validate(raw, report)

    def test_missing_changed_and_mistyped_observations(self):
        for name in NAMES:
            raw, original = synthetic_report(load(name)); validate = validator(name); validate(raw, original)
            for kind in ('missing', 'extra-dispatch', 'boolean-counter', 'changed-input'):
                report = copy.deepcopy(original)
                if kind == 'missing': report['steps'].pop()
                if kind == 'extra-dispatch': report['steps'][0]['actual']['effects']['dispatch'] = 1
                if kind == 'boolean-counter': report['steps'][0]['actual']['effects']['dispatch'] = False
                if kind == 'changed-input': report['steps'][0]['input'] = {}
                with self.subTest(name=name, kind=kind), self.assertRaises(ValueError): validate(raw, report)

    def test_unsupported_recovery_cannot_resume_or_claim_observations(self):
        raw, report = synthetic_report(load('guard-scope-recovery'))
        report['status'] = 'INCOMPLETE'; report['steps'][3]['status'] = 'UNSUPPORTED'
        report['steps'][3]['actual'].update(verdict='UNSUPPORTED', output={}, effects={})
        for step in report['steps'][4:]: step['status'] = 'NOT_RUN'; step.pop('actual')
        guard_validate(raw, report)
        report['steps'][4]['actual'] = {'verdict':'ACCEPT'}
        with self.assertRaises(ValueError): guard_validate(raw, report)

if __name__ == '__main__': unittest.main()
