"""Guard the sage-spec wire/HTTP source import and bounded adapter inputs."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import generate_wire_http_binding_suite as vectors


class WireHTTPBindingSuiteTests(unittest.TestCase):
    def test_fixed_source_and_six_derived_cases(self):
        result = vectors.check()
        self.assertEqual(result['cases'], 6)
        self.assertEqual(result['boundary_cases'], 2)
        self.assertEqual(result['implementation_conformance'], 'NOT_ESTABLISHED')
        suite = json.loads(vectors.OUTPUT.read_bytes())
        self.assertEqual([case['id'] for case in suite['cases']], [
            'wire-http-request-base', 'wire-http-response-base',
            'wire-http-request-digest', 'wire-http-response-digest',
            'wire-http-request-boundary', 'wire-http-response-boundary'])
        self.assertEqual([case['operation'] for case in suite['cases'][-2:]],
                         ['sage.http.verify', 'sage.http.verify'])

    def test_source_mutation_fails_before_case_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'vectors/0.10.0').mkdir(parents=True)
            for source in (vectors.SOURCE, vectors.OUTPUT):
                shutil.copyfile(source, root / 'vectors/0.10.0' / source.name)
            path = root / 'vectors/0.10.0/wire-http-binding-source.json'
            raw = json.loads(path.read_text())
            raw['status'] = 'IMPLEMENTATION_CONFORMANT'
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError, 'source fixture hash'):
                vectors.check(root)

    def test_expected_result_cannot_be_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'vectors/0.10.0').mkdir(parents=True)
            for source in (vectors.SOURCE, vectors.OUTPUT):
                shutil.copyfile(source, root / 'vectors/0.10.0' / source.name)
            path = root / 'vectors/0.10.0/wire-http-binding.json'
            suite = json.loads(path.read_text())
            suite['cases'][-1]['expected']['verdict'] = 'REJECT'
            path.write_text(json.dumps(suite))
            with self.assertRaisesRegex(ValueError, 'derived suite bytes differ'):
                vectors.check(root)

    def test_boundary_controls_preserve_exact_wire_bodies(self):
        source = json.loads(vectors.SOURCE.read_bytes())
        suite = vectors.build_suite(source)
        request = vectors.raw_http(source['http_request'])
        response = vectors.raw_http(source['http_response'], response=True)
        for case in suite['cases']:
            control = case['input']
            self.assertEqual(bytes.fromhex(control['request_hex']), request)
            self.assertEqual(bytes.fromhex(control['response_hex']),
                             response if 'response' in case['id'] else b'')
        self.assertEqual(suite['cases'][-1]['input']['now_unix'],
                         source['reference_now'])


if __name__ == '__main__':
    unittest.main()
