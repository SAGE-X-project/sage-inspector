"""Guard rejection and error-report contracts using fixed observations only."""
import copy
import json
import unittest
from inspect_guard import ROOT, validate_scenario
from scenario_test_support import synthetic_report

NAMES=('guard-gate-skip','guard-gate-timeout','guard-gate-exception',
       'guard-changed-inner-envelope','guard-check-load-replacement','guard-uncovered-load')


def fixture(name):
    return json.loads((ROOT/'vectors/0.10.0/guard-scenarios'/(name+'.json')).read_text())


def rejection_index(f):
    return next(i for i,s in enumerate(f['steps']) if s['expected']['verdict']=='REJECT')


class GuardGateTests(unittest.TestCase):
    def test_missing_timeout_and_exception_close_policy(self):
        for name in NAMES[:3]:
            f=fixture(name)
            self.assertEqual(f['steps'][1]['input']['action'],'gate-failure')
            self.assertIs(f['steps'][2]['expected']['output']['policy_active'],False)
            self.assertEqual(f['steps'][3]['expected'],dict(verdict='REJECT',output={}))
            for s in f['steps']: self.assertTrue(all(v==0 for v in s['effects'].values()))

    def test_failed_measurement_blocks_execution(self):
        for name in NAMES[-2:]:
            f=fixture(name);i=rejection_index(f)
            self.assertEqual(f['steps'][i]['effects']['dispatch'],0)
            self.assertEqual(f['steps'][i]['effects'],f['steps'][i-1]['effects'])
        f=fixture('guard-uncovered-load')
        self.assertIs(f['steps'][2]['expected']['output']['measured'],False)
        f=fixture('guard-check-load-replacement')
        entries=f['steps'][-1]['expected']['output']['entries']
        self.assertEqual({v['state'] for v in entries.values()},{'REJECTED'})

    def test_changed_request_does_not_replace_original(self):
        f=fixture('guard-changed-inner-envelope')
        self.assertEqual(f['steps'][1]['expected']['verdict'],'ACCEPT')
        self.assertEqual(f['steps'][3]['expected']['verdict'],'REJECT')
        self.assertEqual(f['steps'][2]['expected']['output']['entries'],f['steps'][4]['expected']['output']['entries'])
        self.assertEqual(f['steps'][5]['expected']['verdict'],'ACCEPT')
        self.assertEqual(f['steps'][5]['effects']['dispatch'],1)

    def test_rejection_does_not_hide_acceptance_or_effects(self):
        for name in NAMES:
            f=fixture(name);raw,original=synthetic_report(f);validate_scenario(raw,original);i=rejection_index(f)
            for kind in ('accept','dispatch','responses','result_signatures','missing-effects','wrong-id'):
                r=copy.deepcopy(original);a=r['steps'][i]['actual']
                if kind=='accept':a['verdict']='ACCEPT'
                elif kind=='missing-effects':a['effects']={}
                elif kind=='wrong-id':a['step_id']='unrelated'
                else:a['effects'][kind]+=1
                with self.subTest(name=name,kind=kind),self.assertRaises(ValueError):validate_scenario(raw,r)

    def test_missing_gate_and_unexecuted_observation_rejected(self):
        raw,original=synthetic_report(fixture('guard-gate-skip'))
        r=copy.deepcopy(original);r['steps'].pop(1)
        with self.assertRaises(ValueError):validate_scenario(raw,r)
        r=copy.deepcopy(original);r['status']='INCOMPLETE';r['steps'][1]['status']='UNSUPPORTED'
        r['steps'][1]['actual'].update(verdict='UNSUPPORTED',output={},effects={})
        for s in r['steps'][2:]:s['status']='NOT_RUN';s.pop('actual')
        validate_scenario(raw,r)
        r['steps'][2]['actual']={'verdict':'REJECT'}
        with self.assertRaises(ValueError):validate_scenario(raw,r)

    def test_gate_failure_control_is_not_a_message_rejection(self):
        # Arming a controlled failure succeeds; the later submission must reject.
        f=fixture('guard-gate-timeout');raw,r=synthetic_report(f)
        self.assertEqual(f['steps'][1]['expected']['verdict'],'ACCEPT')
        r['steps'][1]['actual']['verdict']='REJECT'
        with self.assertRaises(ValueError):validate_scenario(raw,r)

if __name__=='__main__':unittest.main()
