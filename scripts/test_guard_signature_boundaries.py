import copy
import unittest
from check_guard_signature_boundaries import fixtures, validate_response, audit


class BoundaryTests(unittest.TestCase):
    def test_independent_crypto_audit(self):
        self.assertEqual(audit(), {'cases':10,'valid':8,'invalid':2})

    def test_membership_and_positive_controls(self):
        rows=fixtures()
        self.assertEqual(len({c['id'] for c in rows}),10)
        self.assertEqual(sum(c['expected']=='ACCEPT' for c in rows),2)
        for role in ('intent','result'):
            self.assertEqual(sum(c['id'].startswith(role+'-') for c in rows),5)

    def test_response_controls(self):
        for c in fixtures():
            response=dict(schema_version=1,case_id=c['id'],verdict=c['expected'],output={'valid':True} if c['expected']=='ACCEPT' else {})
            validate_response(c,response)
            for mutation in (lambda r:r.update(case_id='other'),lambda r:r.update(verdict='UNSUPPORTED'),lambda r:r.update(schema_version=True),lambda r:r.update(output={'unexpected':True}),lambda r:r.update(output={'valid':1})):
                r=copy.deepcopy(response);mutation(r)
                with self.assertRaises(ValueError):validate_response(c,r)


if __name__=='__main__':unittest.main()
