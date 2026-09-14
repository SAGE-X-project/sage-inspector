"""Ordered close/receive contract tests; no concurrent core calls."""
import copy
import json
import unittest
from inspect_session import ROOT, validate_scenario
from scenario_test_support import synthetic_report


def close_fixture(order):
    base = json.loads((ROOT/'vectors/0.10.0/session-scenarios/session-close.json').read_text())
    # Full known-valid inputs avoid using the old shorthand rejection input.
    other = json.loads((ROOT/'vectors/0.10.0/session-scenarios/session-absolute-boundary.json').read_text())
    receive0 = copy.deepcopy(base['steps'][1])
    receive1 = copy.deepcopy(other['steps'][2])
    create, closing, inspect = [copy.deepcopy(base['steps'][i]) for i in (0,3,4)]
    count = 0 if order == 'close-first' else 1
    after = receive0 if order in ('close-first','replay-after-close') else receive1
    after = copy.deepcopy(after)
    after['expected'] = dict(verdict='REJECT',output={})
    effects = dict(accepted=count, emitted=0, allocated=0, dispatch=count, confirmations=0, closed=1)
    for step in (closing,inspect,after): step['effects'] = copy.deepcopy(effects)
    inspect['expected']['output'] = dict(state='CLOSED', next_send=0, received=[] if count==0 else [0], last_activity=0, keys_available=False)
    steps = [create]
    if count: steps.append(receive0)
    steps += [closing,inspect,after,copy.deepcopy(inspect)]
    for i,s in enumerate(steps): s['id'] = 'ordered-'+str(i)
    base['id'] = 'unit-close-'+order; base['steps'] = steps
    return base


class CloseOrderTests(unittest.TestCase):
    def test_ordered_expectations(self):
        for order in ('close-first','receive-first','replay-after-close'):
            f=close_fixture(order); steps=f['steps']; raw,report=synthetic_report(f)
            validate_scenario(raw,report)
            close=next(i for i,s in enumerate(steps) if s['input'].get('action')=='close')
            self.assertEqual(close,1 if order=='close-first' else 2)
            self.assertEqual(steps[-2]['input']['seq'],1 if order=='receive-first' else 0)
            self.assertIn('record_hex',steps[-2]['input'])
            self.assertTrue(steps[-2]['input']['signature_verified'])
            self.assertEqual(steps[-2]['expected'],dict(verdict='REJECT',output={}))
            self.assertEqual(steps[-1]['effects']['dispatch'],0 if order=='close-first' else 1)
            self.assertIs(steps[-1]['expected']['output']['keys_available'],False)

    def test_late_acceptance_and_effects_rejected(self):
        for order in ('close-first','receive-first','replay-after-close'):
            raw,original=synthetic_report(close_fixture(order))
            for field in ('verdict','accepted','dispatch','allocated','emitted','confirmations','closed'):
                report=copy.deepcopy(original); actual=report['steps'][-2]['actual']
                if field=='verdict': actual['verdict']='ACCEPT'
                else: actual['effects'][field]+=1
                with self.subTest(order=order,field=field),self.assertRaises(ValueError): validate_scenario(raw,report)

    def test_closed_state_cannot_reactivate(self):
        raw,original=synthetic_report(close_fixture('receive-first'))
        for key,value in [('state','ESTABLISHED'),('keys_available',True),('received',[0,1]),('next_send',1),('last_activity',1)]:
            report=copy.deepcopy(original);report['steps'][-1]['actual']['output'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_scenario(raw,report)

    def test_order_and_identity_cannot_be_reassigned(self):
        raw,original=synthetic_report(close_fixture('receive-first'))
        for kind in ('swap','late-id','missing-close'):
            report=copy.deepcopy(original)
            if kind=='swap': report['steps'][1],report['steps'][2]=report['steps'][2],report['steps'][1]
            if kind=='late-id': report['steps'][-2]['actual']['step_id']=report['steps'][1]['step_id']
            if kind=='missing-close': report['steps'].pop(2)
            with self.subTest(kind=kind),self.assertRaises(ValueError): validate_scenario(raw,report)

    def test_unsupported_close_stops_following_observations(self):
        raw,report=synthetic_report(close_fixture('close-first'))
        report['status']='INCOMPLETE';report['steps'][1]['status']='UNSUPPORTED'
        report['steps'][1]['actual'].update(verdict='UNSUPPORTED',output={},effects={})
        for step in report['steps'][2:]: step['status']='NOT_RUN';step.pop('actual')
        validate_scenario(raw,report)
        report['steps'][2]['actual']={'verdict':'ACCEPT'}
        with self.assertRaises(ValueError): validate_scenario(raw,report)

if __name__=='__main__': unittest.main()
