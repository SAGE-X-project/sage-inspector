"""Independent contract admission and scope tests; synthetic rows are not native evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import did_profile_observation as m


def rows(normative=True):
    result=[]
    for c in m.fixtures():
        if c['id'] in m.UNSUPPORTED:continue
        want=copy.deepcopy(c['expected']);out={'source_calls':want['source_calls'],'network_attempts':0,'responses':[]}
        for r in want['responses']:
            body=r.pop('body')
            if c['input']['interface']=='did-resolution-tls' and body is None:
                body={'type':r['problem_type'],'title':'Fixture problem','status':r['status'],'sageCode':r['sage_code']}
            if not normative and c['id']=='didp-02-json-envelope':del body['didDocumentMetadata']['deactivated']
            if not normative and c['id']=='didp-05-unsupported-accept':del body['sageCode'];r['sage_code']=''
            out['responses'].append(r|{'body_hex':m.canonical(body).hex() if body is not None else ''})
        result.append({'id':c['id'],'input_sha256':c['input_sha256'],'actual':out})
    return result


class Contracts(unittest.TestCase):
    def test_complete_contracts_and_no_evidence(self):
        c=m.fixtures();self.assertEqual(len(c),28)
        r=m.assess([]);self.assertEqual(r['status_counts'],{'NOT_RUN':580,'UNSUPPORTED':3})
        self.assertEqual(r['conformance'],'NOT_ESTABLISHED')
        self.assertFalse(m.known_gap_only(r))
        with patch.object(m,'FIXTURE_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'fixture drift'):m.fixtures()

    def test_independent_success_remains_partial(self):
        r=m.assess(rows());self.assertEqual(r['status_counts'],{'NOT_RUN':555,'PARTIAL':25,'UNSUPPORTED':3})
        self.assertEqual(r['evidence_kind'],'reported-library-output')
        self.assertFalse(m.known_gap_only(r))

    def test_known_gaps_stay_fail_and_other_mutations_are_not_tolerated(self):
        values=rows(False);r=m.assess(values)
        self.assertEqual(r['status_counts'],{'NOT_RUN':555,'PARTIAL':23,'FAIL':2,'UNSUPPORTED':3})
        self.assertTrue(m.known_gap_only(r))
        for change in ('body','count','code','extra_failure'):
            bad=copy.deepcopy(values)
            target=next(x for x in bad if x['id']=='didp-05-unsupported-accept')
            if change=='body':
                b=m.load(bytes.fromhex(target['actual']['responses'][0]['body_hex']));b['sageCode']=''
                target['actual']['responses'][0]['body_hex']=m.canonical(b).hex()
            elif change=='count':target['actual']['source_calls']=1
            elif change=='code':target['actual']['responses'][0]['sage_code']='record.stale'
            else:bad[0]['actual']['source_calls']=2
            self.assertFalse(m.known_gap_only(m.assess(bad)))
        report=m.assess(values);report['observations']=[x for x in values if x['id']!='didp-05-unsupported-accept']
        self.assertFalse(m.known_gap_only(report))

    def test_closed_observation_admission(self):
        base=rows()[0]
        for mutation in ('duplicate','unknown','unsupported','hash','self_pass','bool_counter','bool_status','extra','bad_hex','json_duplicate','wrong_body_type','wrong_response_count'):
            v=copy.deepcopy(base);vals=[v]
            if mutation=='duplicate':vals=[v,v]
            elif mutation=='unknown':v['id']='unknown'
            elif mutation=='unsupported':v['id']=next(iter(m.UNSUPPORTED))
            elif mutation=='hash':v['input_sha256']='0'*64
            elif mutation=='self_pass':v['status']='PASS'
            elif mutation=='bool_counter':v['actual']['source_calls']=True
            elif mutation=='bool_status':v['actual']['responses'][0]['status']=True
            elif mutation=='extra':v['actual']['responses'][0]['other']='extra'
            elif mutation=='bad_hex':v['actual']['responses'][0]['body_hex']='zz'
            elif mutation=='json_duplicate':v['actual']['responses'][0]['body_hex']=b'{"id":1,"id":2}'.hex()
            elif mutation=='wrong_body_type':v['actual']['responses'][0]['body_hex']=b'[]'.hex()
            else:v['actual']['responses']=[]
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.assess(vals)
        for v in ({},[base]*26):
            with self.assertRaises(ValueError):m.assess(v)

    def test_content_and_error_mismatches(self):
        values=rows()
        for id in ('didp-01-did-1-1-shape','didp-02-json-ld-rejected','didp-05-not-found'):
            v=copy.deepcopy(next(v for v in values if v['id']==id))
            v['actual']['responses'][0]['body_hex']=b'{}'.hex()
            r=m.assess([v]);self.assertEqual(next(c['status'] for c in r['cases'] if c['id']==id),'FAIL')
        c=next(c for c in m.fixtures() if c['id']=='didp-05-not-found')
        a=m.checked_actual(next(v['actual'] for v in values if v['id']==c['id']),1)
        for key,value in (('extra',True),('type','wrong'),('status',True),('title',''),('detail',42)):
            bad=copy.deepcopy(a);bad['responses'][0]['body'][key]=value
            self.assertFalse(m.matches(bad,c['expected'],'did-resolution-tls'))
        bad=copy.deepcopy(a);del bad['responses'][0]['body']['type'];self.assertFalse(m.matches(bad,c['expected'],'did-resolution-tls'))

    def test_json_body_types_are_not_python_numeric_aliases(self):
        values=rows()
        for id,member,replacement in (('didp-02-json-envelope','deactivated',0),('didp-05-deactivated','deactivated',1),('didp-02-json-envelope','observedTime',1800000000.0)):
            v=copy.deepcopy(next(v for v in values if v['id']==id))
            body=m.load(bytes.fromhex(v['actual']['responses'][0]['body_hex']))
            if member=='deactivated':body['didDocumentMetadata'][member]=replacement
            else:body['didDocumentMetadata']['sage'][member]=replacement
            v['actual']['responses'][0]['body_hex']=m.canonical(body).hex()
            report=m.assess([v]);self.assertEqual(next(c['status'] for c in report['cases'] if c['id']==id),'FAIL')

    def test_cli_scopes_and_failed_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'report.json'
            def invoke(args):
                with patch.object(sys,'argv',['did-profile','--output',str(target)]+args):m.main()
            invoke([])
            self.assertEqual(json.loads(target.read_text())['status_counts']['NOT_RUN'],580)
            with self.assertRaises(SystemExit):invoke(['--record-known-gap'])
            with patch.object(m,'run_native',return_value=m.assess(rows(False))):
                with self.assertRaises(SystemExit):invoke(['--native'])
                invoke(['--native','--record-known-gap'])
            with patch.object(m,'run_native',return_value=m.assess(rows())):invoke(['--native'])

if __name__=='__main__':unittest.main()
