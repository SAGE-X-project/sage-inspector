"""Validate proposal traceability only; no protocol or cryptographic execution."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
ROOT=Path(__file__).resolve().parent

def unique(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise ValueError('duplicate JSON member')
        value[k]=v
    return value

def load(path):return json.loads(path.read_bytes(),object_pairs_hook=unique)
def require(value,message):
    if not value:raise ValueError(message)
def validate(basis,plan,text,schema):
    require(basis['status']=='PROPOSAL_NOT_ADOPTED' and basis['conformance']=='NOT_ESTABLISHED','proposal promotion')
    require(basis['sage_version']=='0.10.0' and basis['mcp_version']=='2025-06-18','version mismatch')
    require(basis['lifecycle']=={'NOT_RUN':37},'historical promotion')
    require(basis['tool_schema_sha256']==hashlib.sha256(schema).hexdigest(),'schema mismatch')
    require(basis['local_design']['state']=='PRE_EXISTING_UNCOMMITTED_DESIGN','baseline provenance')
    require(all(re.fullmatch('[0-9a-f]{64}',v) for v in basis['local_design']['files'].values()),'source hash')
    require(plan['kind']=='proposal-case-plan' and plan['status']=='NOT_RUN' and plan['conformance']=='NOT_ESTABLISHED','plan promotion')
    rules=set(re.findall(r'^## (MSET-\d{2}) —',text,re.M));require(rules=={f'MSET-{n:02d}' for n in range(1,9)},'rule catalog')
    seen=set();covered={rule:0 for rule in rules}
    for c in plan['cases']:
        require(set(c)=={'id','rule','precondition','input','expected','status','evidence'},'case schema')
        require(c['id'] not in seen and c['id'].startswith(c['rule'].lower()+'-'),'case identity');seen.add(c['id'])
        require(c['rule'] in rules and c['status']=='NOT_RUN','case promotion or rule')
        require(c['expected'] in {'ALLOW_SETUP','CLOSE','DENY_EFFECT','READY','NO_REEXECUTION','DENY_CLAIM','ALLOW_OPERATION_CHECKS'},'undefined outcome')
        require(all(type(c[k]) is str and len(c[k])>=15 for k in ('precondition','input','evidence')),'missing scenario evidence')
        covered[c['rule']]+=1
    require(all(n>=3 for n in covered.values()),'missing rule cases')
    return len(seen)

def inputs():return load(ROOT/'basis.json'),load(ROOT/'cases.json'),(ROOT/'README.md').read_text(),(ROOT/'tool.json').read_bytes()
class Integrity(unittest.TestCase):
    def setUp(self):self.values=inputs()
    def reject(self,change):
        values=copy.deepcopy(self.values);change(values)
        with self.assertRaises(ValueError):validate(*values)
    def test_valid(self):self.assertEqual(validate(*self.values),40)
    def test_promotion(self):
        self.reject(lambda v:v[0].update(status='ADOPTED'))
        self.reject(lambda v:v[1]['cases'][0].update(status='PASS'))
    def test_missing_rule(self):self.reject(lambda v:v[1].update(cases=[x for x in v[1]['cases'] if x['rule']!='MSET-04']))
    def test_duplicate(self):self.reject(lambda v:v[1]['cases'].append(v[1]['cases'][0]))
    def test_schema_and_history(self):
        self.reject(lambda v:v[0].update(tool_schema_sha256='0'*64))
        self.reject(lambda v:v[0].update(lifecycle={'PASS':37}))

def validate_review(review,plan,files):
    require(review['kind']=='proposal-counterexample-review','review kind')
    require(review['method']=='SEPARATE_PASS_SAME_AUTHORING_AGENT','review independence claim')
    require(review['verdict']=='REVISED_DRAFT_EXTERNAL_REVIEW_REQUIRED' and review['adoption']=='PROPOSAL_NOT_ADOPTED','review promotion')
    require(review['protocol_execution']=='NOT_RUN' and review['conformance']=='NOT_ESTABLISHED','runtime promotion')
    require(review['reviewed_revision']=='48858011b75f69c72f03c0fde1c17a1edc538815','review baseline')
    require(re.fullmatch('[0-9a-f]{64}',review['reviewed_readme_sha256']) is not None,'review input hash')
    require(set(review['corrected_files'])=={'README.md','cases.json','tool.json','review.md'},'review file set')
    for name,digest in review['corrected_files'].items():
        require(hashlib.sha256(files[name]).hexdigest()==digest,'review artifact hash')
    expected={'output-publication','request-id-history','deadline-linearization','replay-state-order','descriptor-comparison'}
    require(len(review['findings'])==5 and {r['id'] for r in review['findings']}==expected,'finding catalog')
    cases={c['id']:c for c in plan['cases']};seen=set()
    for row in review['findings']:
        require(set(row)=={'id','severity','rule','status','cases'},'finding schema')
        require(row['status']=='RESOLVED_IN_DRAFT' and row['severity'] in {'HIGH','MEDIUM'},'finding claim')
        require(row['cases'] and len(set(row['cases']))==len(row['cases']),'finding case membership')
        for ident in row['cases']:
            require(ident in cases and ident not in seen and cases[ident]['rule']==row['rule'] and cases[ident]['status']=='NOT_RUN','finding traceability')
            seen.add(ident)
    require(len(seen)==9,'review case count')

def review_inputs():
    return load(ROOT/'review.json'),load(ROOT/'cases.json'),{name:(ROOT/name).read_bytes() for name in ('README.md','cases.json','tool.json','review.md')}

class ReviewIntegrity(unittest.TestCase):
    def test_valid_review(self):validate_review(*review_inputs())
    def test_promotion_and_missing_cases(self):
        for change in (lambda r:r.update(method='EXTERNAL_AUDIT'),lambda r:r.update(protocol_execution='PASS'),lambda r:r['findings'][0].update(cases=['missing'])):
            r,p,f=review_inputs();change(r)
            with self.assertRaises(ValueError):validate_review(r,p,f)
    def test_changed_review_artifact(self):
        r,p,f=review_inputs();f['README.md']+=b'changed'
        with self.assertRaises(ValueError):validate_review(r,p,f)

if __name__=='__main__':
    if '--self-test' in sys.argv:unittest.main(argv=[sys.argv[0]])
    else:
        count=validate(*inputs());validate_review(*review_inputs())
        print(f'Document consistency PASS: {count} planned cases and five reviewed findings; all protocol execution NOT_RUN; proposal not adopted.')
