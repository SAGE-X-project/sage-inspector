import copy
import json
import unittest
from inspect_close_race import evaluate
from check_close_evidence import ROOT, BASE, check, validate


def observation(index, start, finish, verdict='ACCEPT', plain=''):
    return dict(index=index, started_ns=start, finished_ns=finish, verdict=verdict, plaintext_hex=plain)


def fixture(mode='race', overlap=True):
    rows = []
    for direction in ('c2s', 's2c'):
        for number in range(1 if mode == 'control' else 16):
            workers = [observation(i, 3+i, 15+i if overlap and mode == 'race' else 4+i, plain=bytes([i+1]).hex()) for i in range(8)]
            closing = observation(8, 10 if overlap and mode == 'race' else 23, 25)
            rows.append(dict(mode=mode, direction=direction, round=number, participants=9, workers=workers, close=closing,
                             fresh_control=observation(8, 1, 2, plain='09'), after_close=observation(8, 30, 31, 'REJECT')))
    return rows


class CloseInspectionTests(unittest.TestCase):
    def test_archive(self):
        self.assertEqual(check()['go_status'], 'FAIL')
        self.assertEqual(check()['rust_status'], 'UNSUPPORTED')

    def test_process_failures_never_pass(self):
        for code, stderr, timeout, reason in [(66, 'WARNING: DATA RACE', False, 'DATA_RACE'), (2, 'panic', False, 'PROCESS_FAILURE'), (None, '', True, 'TIMEOUT')]:
            r = evaluate('', stderr, code, timeout, 'race')
            self.assertEqual((r['status'], r['reason']), ('FAIL', reason))

    def test_bounded_success_and_no_overlap(self):
        for mode, overlap, status in [('race', True, 'PASS'), ('race', False, 'INCOMPLETE'), ('control', False, 'PASS')]:
            self.assertEqual(evaluate('\n'.join(map(json.dumps, fixture(mode, overlap))), '', 0, False, mode)['status'], status)

    def test_invalid_controls_and_results(self):
        for kind in ('fresh', 'post-close', 'plaintext', 'index', 'missing', 'late-accept', 'timestamp', 'direction', 'participants'):
            rows = fixture(); row = rows[0]
            if kind == 'fresh': row['fresh_control']['verdict'] = 'REJECT'
            if kind == 'post-close': row['after_close']['verdict'] = 'ACCEPT'
            if kind == 'plaintext': row['workers'][0]['plaintext_hex'] = 'ff'
            if kind == 'index': row['workers'][1]['index'] = 0
            if kind == 'missing': rows.pop()
            if kind == 'late-accept': row['workers'][0].update(started_ns=26, finished_ns=27)
            if kind == 'timestamp': row['close']['started_ns'] = True
            if kind == 'direction': row['direction'] = 's2c'
            if kind == 'participants': row['participants'] = 8
            with self.subTest(kind=kind):
                self.assertEqual(evaluate('\n'.join(map(json.dumps, rows)), '', 0, False, 'race')['status'], 'FAIL')
        duplicate = json.dumps(fixture()[0]).replace('"participants": 9', '"participants": 9, "participants": 9')
        self.assertEqual(evaluate(duplicate, '', 0, False, 'race')['status'], 'FAIL')

    def test_report_cannot_hide_detector_failure(self):
        original = json.loads((ROOT/(BASE+'report.json')).read_text())
        logs = {p:(ROOT/(BASE+p)).read_text() for p in ('control.stdout','control.stderr','race.stdout','race.stderr')}
        for kind in ('pass', 'returncode', 'missing', 'race-build', 'rust', 'controls'):
            r = copy.deepcopy(original)
            if kind == 'pass': r['go_status'] = 'PASS'
            if kind == 'returncode': r['runs'][1]['returncode'] = 0
            if kind == 'missing': r['runs'].pop()
            if kind == 'race-build': r['go_build_info'] = 'plain build'
            if kind == 'rust': r['rust_status'] = 'PASS'
            if kind == 'controls': r['environment_controls']['GORACE'] = 'exitcode=0'
            with self.subTest(kind=kind), self.assertRaises(ValueError): validate(r, logs)

if __name__ == '__main__':
    unittest.main()
