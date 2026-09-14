"""Protocol link expectation and Inspector judgment tests, not core certification."""
import copy
import hashlib
import json
import unittest
from inspect_session import ROOT, validate_scenario
from inspect_hpke import validate_report
from scenario_test_support import synthetic_report
from protocol_test_support import selected_suite, websocket_suite


def primitive_report(suite):
    raw=json.dumps(suite).encode()
    report=dict(schema_version=1,protocol_version='0.10.0',suite_id=suite['id'],suite_sha256=hashlib.sha256(raw).hexdigest(),status='PASS',counts=dict(PASS=len(suite['cases']),FAIL=0,UNSUPPORTED=0,NOT_RUN=0),results=[])
    for c in suite['cases']:
        report['results'].append(dict(case_id=c['id'],operation=c['operation'],rule_ids=c['rule_ids'],expected=copy.deepcopy(c['expected']),status='PASS',actual=dict(schema_version=1,case_id=c['id'],**copy.deepcopy(c['expected']))))
    return raw,report


def hpke_scenario(name):
    return json.loads((ROOT/'vectors/0.10.0/hpke-scenarios'/('hpke-'+name+'.json')).read_text())


class ProtocolBindingTests(unittest.TestCase):
    def test_transcript_is_the_only_changed_record_context(self):
        cases={c['id']:c for c in selected_suite('session-records')['cases']}
        positive=cases['c2s-open-0'];negative=cases['transcript']
        changed=copy.deepcopy(negative['input']);changed['th_hex']=positive['input']['th_hex']
        self.assertEqual(changed,positive['input'])
        self.assertNotEqual(negative['input']['th_hex'],positive['input']['th_hex'])
        self.assertEqual((positive['expected']['verdict'],negative['expected']['verdict']),('ACCEPT','REJECT'))

    def test_hpke_confirmation_and_pending_binding(self):
        cases={c['id']:c for c in selected_suite('hpke-schedule')['cases']}
        self.assertEqual(cases['completion-valid']['expected']['verdict'],'ACCEPT')
        for name in ('wrong-ack','different-pending-request','unsigned-completion','unknown-transcript-member'):
            self.assertEqual(cases[name]['expected']['verdict'],'REJECT')
            self.assertNotEqual(cases[name]['input'],cases['completion-valid']['input'])
        for name in ('valid','wrong-ack','wrong-pending'):
            f=hpke_scenario(name);raw,report=synthetic_report(f);validate_scenario(raw,report)
            self.assertEqual(f['steps'][1]['effects'],dict(sessions_created=1 if name=='valid' else 0,pending_destroyed=1))
            self.assertEqual(f['steps'][2]['expected']['output'],dict(state='ESTABLISHED' if name=='valid' else 'CLOSED',pending_present=False))
            report['steps'][1]['actual']['effects']['sessions_created']+=1
            with self.assertRaises(ValueError):validate_scenario(raw,report)

    def test_valid_signature_does_not_imply_request_binding(self):
        full={c['id']:c for c in selected_suite('http-boundaries')['cases']}
        inner=json.loads((ROOT/'vectors/0.10.0/http-envelope-primitives.json').read_text())
        inner={c['id']:c for c in inner['cases']}
        for name in ('wrong-request-hash','stale-hash-with-valid-outer-binding'):
            self.assertEqual(inner[name+'-inner-signature']['expected']['verdict'],'ACCEPT')
            self.assertEqual(full[name]['expected']['verdict'],'REJECT')
        self.assertEqual(full['missing-stored-request']['expected']['verdict'],'REJECT')
        self.assertEqual(full['valid-response']['expected']['verdict'],'ACCEPT')

    def test_http_response_requires_original_request(self):
        cases={c['id']:c for c in selected_suite('http-signatures')['cases']}
        self.assertEqual(cases['base-sage-response']['expected']['verdict'],'ACCEPT')
        for name in ('base-missing-request','archive-response-wrong-request-signature'):
            self.assertEqual(cases[name]['expected']['verdict'],'REJECT')

    def test_websocket_trust_does_not_replace_message_checks(self):
        cases={c['id']:c for c in websocket_suite()['cases']}
        self.assertEqual(''.join(cases['fragmented-message']['input']['fragments_hex']),cases['valid-message']['input']['fragments_hex'][0])
        for name in ('unverified-envelope','wrong-recipient','wrong-request-binding'):
            self.assertIs(cases[name]['input']['tls_authenticated'],True)
            self.assertEqual(cases[name]['expected']['verdict'],'REJECT')
        for name in ('binary-message','compressed-message','untrusted-connection'):
            self.assertEqual(cases[name]['expected']['verdict'],'REJECT')

    def test_wrong_results_and_unsupported_cannot_pass(self):
        suites=[selected_suite(n) for n in ('hpke-schedule','session-records','http-signatures','http-boundaries')]+[websocket_suite()]
        for suite in suites:
            raw,original=primitive_report(suite);validate_report(raw,original)
            for kind in ('accept','identity','missing','unsupported'):
                report=copy.deepcopy(original)
                row=next(r for r in report['results'] if r['expected']['verdict']=='REJECT')
                if kind=='accept':row['actual']['verdict']='ACCEPT'
                if kind=='identity':row['actual']['case_id']='unrelated'
                if kind=='missing':report['results'].pop()
                if kind=='unsupported':row['actual']['verdict']='UNSUPPORTED'
                with self.subTest(suite=suite['id'],kind=kind),self.assertRaises(ValueError):validate_report(raw,report)

if __name__=='__main__':unittest.main()
