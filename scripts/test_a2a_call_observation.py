"""Validate all remaining contracts; policy evidence never certifies ingress."""
import copy
import tempfile
from pathlib import Path
import unittest
from a2a_call_observation import fixtures, assess, combine, main
from a2a_card_observation import assess as card_assess, fixtures as card_fixtures

class CallObservationTests(unittest.TestCase):
    def test_complete_remaining_set_and_unsupported_ingress(self):
        cases=fixtures();self.assertEqual(len(cases),23)
        self.assertEqual(sum(c['execution']=='policy' for c in cases),20)
        report=assess([])
        self.assertEqual(report['status_counts'],{'NOT_RUN':580,'UNSUPPORTED':3})
        unsupported=[c for c in report['cases'] if c['status']=='UNSUPPORTED']
        self.assertTrue(all(c['unsupported_reason'] for c in unsupported))
        self.assertEqual(report['scope']['signed_carriage'],'NOT_RUN')

    def test_matching_outputs_remain_partial(self):
        rows=[{'id':c['id'],'mode':'tls','input_sha256':c['input_sha256'],'actual':c['expected']['tls']} for c in fixtures() if c['execution']=='policy']
        report=assess(rows)
        self.assertEqual(report['status_counts'],{'PARTIAL':20,'UNSUPPORTED':3,'NOT_RUN':560})
        self.assertNotIn('PASS',[c['status'] for c in report['cases']])
        bad=copy.deepcopy(rows);bad[0]['actual']['dispatch_count']=0
        self.assertEqual(sum(c['status']=='FAIL' for c in assess(bad)['cases']),1)
        cards=card_assess([{'id':c['id'],'input_sha256':c['input_sha256'],'actual':c['expected']} for c in card_fixtures()])
        combined=combine(cards,report)
        self.assertEqual(combined['status_counts'],{'PARTIAL':61,'UNSUPPORTED':3,'NOT_RUN':519})
        self.assertEqual(combined['conformance'],'NOT_ESTABLISHED')
        bad=copy.deepcopy(cards);bad['spec_revision']='0'*40
        with self.assertRaises(ValueError):combine(bad,report)
        bad=copy.deepcopy(cards);bad['cases'][0]['status']='PASS'
        with self.assertRaises(ValueError):combine(bad,report)

    def test_forged_or_mistyped_observations_rejected(self):
        c=next(c for c in fixtures() if c['execution']=='policy')
        base={'id':c['id'],'mode':'tls','input_sha256':c['input_sha256'],'actual':c['expected']['tls']}
        for name in ('unknown','duplicate','hash','mode','bool-counter','extra','unsupported'):
            row=copy.deepcopy(base);rows=[row]
            if name=='unknown':row['id']='unknown'
            elif name=='duplicate':rows.append(row)
            elif name=='hash':row['input_sha256']='0'*64
            elif name=='mode':row['mode']='fake'
            elif name=='bool-counter':row['actual']['dispatch_count']=True
            elif name=='extra':row['status']='PASS'
            else:row['id']='a2ab-01-bare-jsonrpc-body'
            with self.subTest(name=name),self.assertRaises(ValueError):assess(rows)

    def test_cli_no_subject_and_errors(self):
        import json,sys
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.json'
            with patch.object(sys,'argv',['observe','--output',str(p)]):main()
            self.assertEqual(json.loads(p.read_bytes())['status_counts']['UNSUPPORTED'],3)
            with patch.object(sys,'argv',['observe','--output',str(p/'missing')]),self.assertRaises(SystemExit) as e:main()
            self.assertEqual(e.exception.code,1)

    def test_include_cards_requires_real_native_execution(self):
        import sys
        from unittest.mock import patch
        with patch.object(sys,'argv',['observe','--include-cards','--output','/private/tmp/not-produced.json']),self.assertRaises(SystemExit) as e:main()
        self.assertEqual(e.exception.code,1)

    def test_unreviewed_compiler_input_rejected(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from a2a_card_observation import compiler_inputs
        with patch('a2a_card_observation.execute',return_value=SimpleNamespace(stdout=b'{"GoFiles":["main.go","unreviewed.go"]}')):
            with self.assertRaisesRegex(ValueError,'unexpected compiler inputs'):
                compiler_inputs('go',Path('/private/tmp'),{})

if __name__=='__main__':unittest.main()
