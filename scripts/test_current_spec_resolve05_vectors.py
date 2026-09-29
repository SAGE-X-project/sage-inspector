"""HTTP resolution vectors enforce exact media and problem mappings."""

import copy
import unittest

import check_current_spec_resolve05_vectors as checker


class Resolve05VectorTests(unittest.TestCase):
    def test_pinned_http_cases_and_problem_controls(self):
        self.assertEqual(checker.check(), (5, 9, 14))

    def test_document_only_cannot_authorize(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        body = good['response']['body']
        changed = copy.deepcopy(good)
        changed['request']['headers']['Accept'] = 'application/did+json'
        changed['response']['headers']['Content-Type'] = 'application/did+json'
        changed['response']['body'] = body['didDocument']
        changed['response']['body_bytes'] = len(checker.json.dumps(
            body['didDocument'], separators=(',', ':')).encode())
        self.assertEqual(checker.decision(changed, body), 'ACCEPT')
        changed['consumer_purpose'] = 'authentication'
        self.assertEqual(checker.decision(changed, body), 'REJECT')


if __name__ == '__main__':
    unittest.main()
