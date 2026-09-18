"""Unit tests for observation evidence, never deployed consensus or core tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from inspect_registry_source010 import ROOT, binding, decode, inspect, observations, sha

BINDING = ROOT/'vectors/0.10.0/registry-source-binding.json'
BUNDLE = ROOT/'vectors/0.10.0/registry-source-observations.json'


def fixture():
    raw = BINDING.read_bytes()
    return raw, binding(raw), decode(BUNDLE.read_bytes())


def validate(bundle, b=None):
    raw, configured, _ = fixture()
    return observations(json.dumps(bundle).encode(), b or configured, sha(raw))


class SourceTests(unittest.TestCase):
    def test_measurements(self):
        _, _, bundle = fixture()
        self.assertEqual(validate(bundle), [dict(operation_id='operation-1', read_ms=20,
            observation_age_ms=10, publication_to_finality_ms=80, publication_measurement='DECLARED')])

    def test_missing_publication_is_not_zero(self):
        _, _, bundle = fixture()
        row = bundle['observations'][0]
        del bundle['artifacts'][row['publication']['evidence']]
        row['publication'] = None
        self.assertIsNone(validate(bundle)[0]['publication_to_finality_ms'])
        self.assertEqual(validate(bundle)[0]['publication_measurement'], 'NOT_RUN')

    def test_observation_rejections(self):
        changes = dict(source='other', chain_id='1', registry_address='0x'+'00'*20,
            code_hash='00'*32, finalized=False, conflicting=True, keys_block_hash='00'*32,
            did='did:sage:eip155:1:wrong:alice', version='01', state='unknown',
            readiness_ms=-1, epoch_started_ms=101, start_ms=121, acquired_ms=131,
            gate_ms=5121, utc_ms=True, block_height=-1, record_digest='00'*32,
            readiness_evidence='00'*32, finality_evidence='00'*32, record_evidence='00'*32)
        for key, value in changes.items():
            with self.subTest(key=key):
                _, _, bundle = fixture()
                bundle['observations'][0][key] = value
                with self.assertRaises(ValueError):
                    validate(bundle)

    def test_age_boundary(self):
        _, b, bundle = fixture()
        b['readiness_max_age_ms'] = 6000
        bundle['observations'][0]['gate_ms'] = 5120
        self.assertEqual(validate(bundle, b)[0]['observation_age_ms'], 5000)
        bundle['observations'][0]['gate_ms'] += 1
        with self.assertRaises(ValueError):
            validate(bundle, b)

    def test_readiness_boundary(self):
        _, _, bundle = fixture()
        bundle['observations'][0]['gate_ms'] = 5100
        validate(bundle)
        bundle['observations'][0]['gate_ms'] += 1
        with self.assertRaises(ValueError):
            validate(bundle)

    def test_restart_and_monotonic_history(self):
        _, _, bundle = fixture()
        first = bundle['observations'][0]
        second = copy.deepcopy(first)
        second.update(operation_id='operation-2', epoch='process-2', epoch_started_ms=0,
                      readiness_ms=1, start_ms=1, acquired_ms=2, gate_ms=3)
        second['publication'] = None
        bundle['observations'].append(second)
        validate(bundle)
        changes = dict(operation_id=first['operation_id'], epoch='process-1',
                       epoch_started_ms=2, utc_ms=999999, block_height=99,
                       block_hash='77'*32, version='0', record_digest='88'*32, state='deactivated')
        for key, value in changes.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(bundle)
                changed['observations'][1][key] = value
                with self.assertRaises(ValueError):
                    validate(changed)

    def test_history_rejects_well_formed_conflicts(self):
        for case in ('version-rollback', 'same-block-update', 'finalized-fork', 'reused-epoch'):
            with self.subTest(case=case):
                _, _, bundle = fixture()
                first = bundle['observations'][0]
                first['version'] = '2'
                second = copy.deepcopy(first)
                second.update(operation_id='second', epoch='second')
                second['publication'] = None
                bundle['observations'].append(second)
                validate(bundle)
                if case == 'version-rollback':
                    second.update(version='1', block_height=101, block_hash='77'*32, keys_block_hash='77'*32)
                elif case == 'same-block-update':
                    second['version'] = '3'
                elif case == 'finalized-fork':
                    second.update(block_hash='77'*32, keys_block_hash='77'*32)
                else:
                    third = copy.deepcopy(first)
                    third.update(operation_id='third', start_ms=140, acquired_ms=150, gate_ms=160)
                    bundle['observations'].append(third)
                with self.assertRaises(ValueError):
                    validate(bundle)

    def test_deployed_label_does_not_certify_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, b, bundle = fixture()
            b['environment'] = 'deployed'
            raw = json.dumps(b).encode()
            bundle['binding_sha256'] = sha(raw)
            (root/'binding.json').write_bytes(raw)
            (root/'bundle.json').write_text(json.dumps(bundle))
            report = inspect(root/'binding.json', root/'bundle.json', root/'output')
            self.assertEqual(report['status'], 'EVIDENCE_VALIDATED')
            self.assertEqual(report['live_chain_verification'], 'NOT_RUN')
            self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')

    def test_terminal_survives_restart(self):
        _, _, bundle = fixture()
        first = bundle['observations'][0]
        first['state'] = 'deactivated'
        second = copy.deepcopy(first)
        second.update(operation_id='second', epoch='second', version='2', state='active')
        second['publication'] = None
        bundle['observations'].append(second)
        with self.assertRaises(ValueError):
            validate(bundle)

    def test_publication_order_and_clock(self):
        for key, value in dict(epoch='other', submitted_ms=91, finalized_ms=121, evidence='00'*32).items():
            with self.subTest(key=key):
                _, _, bundle = fixture()
                bundle['observations'][0]['publication'][key] = value
                with self.assertRaises(ValueError):
                    validate(bundle)

    def test_binding_required_fields(self):
        raw, _, _ = fixture()
        original = json.loads(raw)
        for field in original:
            with self.subTest(field=field):
                changed = dict(original)
                del changed[field]
                with self.assertRaises(ValueError):
                    binding(json.dumps(changed).encode())

    def test_binding_bad_values(self):
        for field, value in dict(schema_version=True, chain_id='01', registry_address='0xABC',
            trust_model='arbitrary-rpc', environment='unknown', readiness_max_age_ms=0,
            code_hash='0x'+'00'*32, source='', finality_policy='\n').items():
            with self.subTest(field=field):
                _, b, _ = fixture()
                b[field] = value
                with self.assertRaises(ValueError):
                    binding(json.dumps(b).encode())

    def test_bundle_identity_and_artifacts(self):
        for change in ('binding', 'observer', 'artifact', 'extra', 'empty', 'duplicate'):
            with self.subTest(change=change):
                _, _, bundle = fixture()
                if change == 'binding': bundle['binding_sha256'] = '00'*32
                if change == 'observer': bundle['observer_sha256'] = '00'*32
                if change == 'artifact': bundle['artifacts'][next(iter(bundle['artifacts']))] = '00'
                if change == 'extra': bundle['artifacts'][sha(b'extra')] = b'extra'.hex()
                if change == 'empty': bundle['observations'] = []
                if change == 'duplicate': bundle['observations'] *= 2
                with self.assertRaises(ValueError):
                    validate(bundle)

    def test_json_and_bounds(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b' '* (4*1024*1024+1)):
            with self.assertRaises(ValueError):
                decode(raw)
        _, _, bundle = fixture()
        bundle['observations'] *= 129
        with self.assertRaises(ValueError):
            validate(bundle)

    def test_reports_preserve_scope_and_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = inspect(None, None, root/'missing')
            self.assertEqual(report['status'], 'NOT_RUN')
            report = inspect(BINDING, None, root/'unobserved')
            self.assertEqual(report['status'], 'NOT_RUN')
            report = inspect(BINDING, BUNDLE, root/'complete')
            self.assertEqual(report['status'], 'EVIDENCE_VALIDATED')
            self.assertEqual(report['live_chain_verification'], 'NOT_RUN')
            self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
            for name, digest in report['files'].items():
                self.assertEqual(sha((root/'complete'/name).read_bytes()), digest)
            with self.assertRaises(FileExistsError):
                inspect(BINDING, BUNDLE, root/'complete')
            with self.assertRaises(ValueError):
                inspect(None, None, ROOT/'docs/evidence/forbidden-new-output')


if __name__ == '__main__':
    unittest.main()
