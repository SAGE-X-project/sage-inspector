"""Refuse incomplete, changed or promoted host qualification evidence.

These units change only the saved report and its log text. They start no host,
signer or attacker program.
"""
import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import inspect_adk_host_qualification as audit


class HostQualificationTests(unittest.TestCase):
    """Run against the latest pinned observation; subclasses cover earlier ones."""
    REVISION = audit.LATEST

    def setUp(self):
        self.profile = audit.PROFILES[self.REVISION]
        self.report = audit.strict_json(self.profile['report'].read_bytes())
        self.lines = bytes.fromhex(self.report['log_hex']).decode().split('\n')[:-1]

    def with_lines(self, lines):
        report = copy.deepcopy(self.report)
        raw = ('\n'.join(lines) + '\n').encode()
        report['log_hex'] = raw.hex()
        report['log_sha256'] = audit.sha(raw)
        return report

    def refused(self, report):
        with self.assertRaises(ValueError):
            audit.check_report(report)

    def test_saved_observation(self):
        summary = audit.check_report(self.report)
        self.assertEqual(summary['status'], 'SEPARATE_ACCOUNT_QUALIFICATION_OBSERVED')
        self.assertEqual(summary['isolation_checks'], self.profile['isolation_checks'])
        self.assertEqual(self.report['adk_revision'], self.REVISION)

    def test_scope_and_provenance_never_promote(self):
        for key in self.profile['scope']:
            report = copy.deepcopy(self.report)
            report['scope'][key] = 'PASS'
            with self.subTest(key=key):
                self.refused(report)
        for key in ('adk_revision', 'go_revision', 'go_module', 'normative_source_revision',
                    'compiler', 'status', 'script', 'kind'):
            report = copy.deepcopy(self.report)
            report[key] = 'unreviewed'
            with self.subTest(key=key):
                self.refused(report)
        report = copy.deepcopy(self.report)
        report['extra'] = True
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['binaries_sha256'] = {'adk-signer': report['binaries_sha256']['adk-signer']}
        self.refused(report)

    def test_every_required_line(self):
        for index in range(len(self.lines)):
            lines = self.lines[:index] + self.lines[index + 1:]
            with self.subTest(line=self.lines[index][:40]):
                self.refused(self.with_lines(lines))

    def test_failed_or_weaker_outcomes(self):
        def replace(old, new):
            return [new if line == old else line for line in self.lines]
        cases = {
            'clock-step': replace('clock observed 8m0s backward-steps=0', 'clock observed 8m0s backward-steps=1'),
            'caller-failed': replace('### caller-exit=0', '### caller-exit=1'),
            'receiver-stopped-early': replace('receiver-was-running', 'receiver-not-running'),
            'isolation-failed': replace('caller-cannot-read-signer-key', 'FAIL caller-read-signer-key'),
            'wrong-output': replace('verified output {"output":5,"success":true}',
                                    'verified output {"output":6,"success":true}'),
            'no-refusal': replace('unapproved call refused', 'unapproved call accepted'),
        }
        for name, lines in cases.items():
            with self.subTest(case=name):
                self.refused(self.with_lines(lines))
        extra = self.lines[:-1] + ['clock backward 1.000 ms at +1s'] + self.lines[-1:]
        self.refused(self.with_lines(extra))
        swapped = list(self.lines)
        a = next(i for i, line in enumerate(swapped) if line.startswith('adk-signer ready'))
        swapped[a], swapped[a + 1] = swapped[a + 1], swapped[a]
        self.refused(self.with_lines(swapped))

    def test_log_integrity_and_kernel(self):
        report = copy.deepcopy(self.report)
        report['log_sha256'] = '0' * 64
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['kernel'] = '0.0.0-other'
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['log_hex'] = report['log_hex'][:-2]
        self.refused(report)

    def test_profiles_do_not_accept_each_other(self):
        for revision, profile in audit.PROFILES.items():
            if revision == self.REVISION:
                continue
            report = copy.deepcopy(self.report)
            report['adk_revision'] = revision
            with self.subTest(revision=revision):
                self.refused(report)

    def test_cli_refuses_output_without_fresh_run_and_never_overwrites(self):
        script = Path(audit.__file__)
        done = subprocess.run([sys.executable, '-B', str(script), '--output', '/tmp/x.json'],
                              capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        done = subprocess.run([sys.executable, '-B', str(script), '--revision', self.REVISION],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / 'none'
            done = subprocess.run([sys.executable, '-B', str(script), '--adk-root', str(missing)],
                                  capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)


class FirstHostQualificationTests(HostQualificationTests):
    REVISION = 'ccc053c898ac83d741c7f667efe48c964f6b7532'


class KEMCustodyHostQualificationTests(HostQualificationTests):
    REVISION = '8111a00c964c9db3c7be4580fbe5308d4f8505b5'


if __name__ == '__main__':
    unittest.main()
