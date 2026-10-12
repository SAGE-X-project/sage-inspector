"""Admission and control pairing; synthetic rows never become native evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import a2a_service_type_observation as m
from a2a_card_observation import assess as assess_cards
from a2a_call_observation import assess as assess_calls, combine as combine_calls


def rows():
    return [{'id':c['id'],'input_sha256':c['input_sha256'],'actual':copy.deepcopy(c['expected'])} for c in m.fixtures()]

def empty_a2a():return combine_calls(assess_cards([]),assess_calls([]))

class ServiceContracts(unittest.TestCase):
    def test_exact_pair_and_no_evidence(self):
        self.assertEqual({c['id'] for c in m.fixtures()},m.IDS)
        self.assertEqual(m.assess([])['status_counts'],{'NOT_RUN':583})
        good=m.assess(rows());self.assertEqual(good['status_counts'],{'NOT_RUN':581,'PARTIAL':2})
        self.assertEqual(good['scope']['protected_transport'],'NOT_RUN')
        self.assertEqual(good['evidence_kind'],'reported-library-output')
        with patch.object(m,'FIXTURE_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'fixture drift'):m.fixtures()

    def test_refusal_requires_accepted_positive_control(self):
        v=rows();negative=next(r for r in v if r['id']=='TABLE-08-N01')
        self.assertEqual(m.assess([negative])['status_counts'],{'NOT_RUN':583})
        positive=next(r for r in v if r['id']=='TABLE-08-P');positive['actual']=copy.deepcopy(negative['actual'])
        r=m.assess(v);self.assertEqual(r['status_counts'],{'NOT_RUN':582,'FAIL':1})
        v=rows();negative=next(r for r in v if r['id']=='TABLE-08-N01');negative['actual']=copy.deepcopy(next(r for r in v if r['id']=='TABLE-08-P')['actual'])
        self.assertEqual(m.assess(v)['status_counts'],{'NOT_RUN':581,'PARTIAL':1,'FAIL':1})

    def test_closed_typed_outputs_and_ids(self):
        for mutation in ('duplicate','unknown','hash','self_pass','number_boolean','interfaces_type','too_many_interfaces','interface_member','extra'):
            v=copy.deepcopy(rows()[0]);values=[v]
            if mutation=='duplicate':values=[v,v]
            elif mutation=='unknown':v['id']='a2ab-03-declared'
            elif mutation=='hash':v['input_sha256']='0'*64
            elif mutation=='self_pass':v['status']='PASS'
            elif mutation=='number_boolean':v['actual']['accepted']=1
            elif mutation=='interfaces_type':v['actual']['interfaces']={}
            elif mutation=='too_many_interfaces':v['actual']['interfaces']=['a']*17
            elif mutation=='interface_member':v['actual']['interfaces']=[True]
            else:v['actual']['other']=False
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.assess(values)
        for v in ({},rows()*2):
            with self.assertRaises(ValueError):m.assess(v)

    def test_only_matching_subjects_and_nonoverlapping_domains_combine(self):
        services=m.assess(rows());combined=m.combine(empty_a2a(),services)
        self.assertEqual(combined['status_counts'],{'NOT_RUN':578,'UNSUPPORTED':3,'PARTIAL':2})
        self.assertEqual(combined['conformance'],'NOT_ESTABLISHED')
        for mutation in ('subject','spec','missing','pass','overlap','unexpected_domain','a2a_pass'):
            a=empty_a2a();s=copy.deepcopy(services)
            if mutation=='subject':s['subject']['revision']='0'*40
            elif mutation=='spec':s['spec_revision']='0'*40
            elif mutation=='missing':s['cases'].pop()
            elif mutation=='pass':next(c for c in s['cases'] if c['id']=='TABLE-08-P')['status']='PASS'
            elif mutation=='overlap':next(c for c in a['cases'] if c['id']=='TABLE-08-P')['status']='PARTIAL'
            elif mutation=='a2a_pass':a['cases'][0]['status']='PASS'
            else:next(c for c in s['cases'] if c['id'] not in m.IDS)['status']='PARTIAL'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.combine(a,s)

    def test_cli_native_requirement_and_failure_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'report.json'
            def call(args):
                with patch.object(sys,'argv',['service','--output',str(output)]+args):m.main()
            call([]);self.assertEqual(json.loads(output.read_text())['status_counts'],{'NOT_RUN':583})
            with self.assertRaises(SystemExit):call(['--include-a2a'])
            with patch.object(m,'run_native',return_value=m.assess(rows())):call(['--native'])
            bad=rows();bad[0]['actual']['version']='wrong'
            with patch.object(m,'run_native',return_value=m.assess(bad)):
                with self.assertRaises(SystemExit):call(['--native'])
                self.assertEqual(json.loads(output.read_text())['status_counts']['FAIL'],1)
            with patch.object(m,'run_native',return_value=m.assess(rows())),patch.object(m,'run_cards',return_value=assess_cards([])),patch.object(m,'run_calls',return_value=assess_calls([])):
                call(['--native','--include-a2a'])

if __name__=='__main__':unittest.main()
