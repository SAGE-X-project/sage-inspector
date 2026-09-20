"""Scenario controls and local CLI execution for the abstract admission model."""
import json,subprocess,sys,tempfile,unittest
from dataclasses import replace
from pathlib import Path
from mcp_setup_model import initial,step,explore,invariant
from check_mcp_setup_model import ROOT,baseline
CLIENT=('send_initialize','send_ok','initialize_result','send_initialized','send_ok','ack','send_list','send_ok','listing')
SERVER=('initialize','send_ok','initialized','send_ok','list','send_ok')
def path(role,events):
    s=initial(role)
    for e in events:s=step(s,e)
    return s
class Scenarios(unittest.TestCase):
    def test_both_roles_reach_readiness(self):
        for role,events in [('client',CLIENT),('server',SERVER)]:
            s=path(role,events);self.assertEqual(s.phase,'READY');self.assertTrue(step(s,'call_2').admitted)
    def test_output_does_not_publish_ready(self):
        s=path('server',SERVER[:-1]);self.assertEqual(s.phase,'OUTPUT_PENDING');self.assertEqual(s.proofs,3)
        self.assertFalse(step(s,'call_2').admitted);self.assertEqual(step(s,'send_fail').phase,'CLOSED')
    def test_deferred_reply_and_overflow(self):
        s=path('client',('send_initialize','initialize_result'));self.assertEqual(s.phase,'OUTPUT_PENDING')
        self.assertEqual(step(s,'initialize_result').phase,'CLOSED')
        s=step(step(s,'send_ok'),'drain');self.assertEqual(s.phase,'INITIALIZE_ACCEPTED')
    def test_partial_send_discards_queued_input(self):
        s=path('client',('send_initialize','initialize_result','send_fail','send_ok','drain'))
        self.assertEqual(s.phase,'CLOSED');self.assertFalse(s.admitted);self.assertEqual(s.queued,'')
    def test_deadline_exact_boundary(self):
        s=path('server',SERVER[:-1])
        self.assertEqual(step(replace(s,now=29999),'send_ok').phase,'READY')
        self.assertEqual(step(replace(s,now=30000),'send_ok').phase,'CLOSED')
    def test_close_beats_late_completion(self):
        for e in ('close','invalidate','clock_failure','rollback','tick_30000'):
            s=step(path('server',SERVER[:-1]),e);self.assertEqual(step(s,'send_ok'),s)
    def test_ready_outlives_setup_timer(self):
        s=step(path('client',CLIENT),'tick_30001');self.assertEqual(s.phase,'READY')
        self.assertEqual(step(s,'invalidate').phase,'CLOSED')
    def test_setup_ids_not_reusable(self):
        for id in (0,1):
            s=step(path('server',SERVER),'call_'+str(id));self.assertEqual(s.phase,'CLOSED');self.assertFalse(s.admitted)
    def test_consumed_replay_survives_inner_rejection(self):
        s=step(initial('server'),'bad_inner');self.assertNotEqual(s.replay,0)
        self.assertEqual(step(s,'initialize'),s)
    def test_finite_graph_nonvacuous(self):
        for role in ('client','server'):
            full=explore(role,3);small=explore(role,2)
            self.assertTrue(full['ready_reachable'] and full['admission_reachable']);self.assertFalse(small['admission_reachable'])
    def test_wrong_order_and_missing_guard_permission(self):
        self.assertEqual(step(initial('client'),'ack').phase,'CLOSED')
        self.assertFalse(step(path('client',CLIENT),'denied_call').admitted)
    def test_monitor_detects_unsafe_model_changes(self):
        before=initial('server')
        with self.assertRaises(AssertionError):invariant(before,'initialize',replace(before,phase='READY',proofs=7))
        pending=path('server',SERVER[:-1])
        with self.assertRaises(AssertionError):invariant(pending,'list',replace(pending,admitted=True))
        accepted=step(before,'bad_inner')
        with self.assertRaises(AssertionError):invariant(accepted,'initialize',replace(accepted,replay=0))
    def test_pinned_proposal(self):self.assertEqual(baseline()['status'],'PROPOSAL_NOT_ADOPTED')
class Runtime(unittest.TestCase):
    def test_cli_report_and_preservation(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'evidence';cmd=[sys.executable,str(ROOT/'scripts/check_mcp_setup_model.py'),'--output',str(out)]
            run=subprocess.run(cmd,capture_output=True,text=True,timeout=30);self.assertEqual(run.returncode,0,run.stderr)
            raw=(out/'report.json').read_bytes();r=json.loads(raw);self.assertEqual(r['status'],'MODEL_CHECKED')
            self.assertFalse(r['actual_core_execution']);self.assertFalse(r['external_review']);self.assertEqual(r['proposal_cases'],{'NOT_RUN':40})
            self.assertEqual(subprocess.run(cmd,capture_output=True,timeout=30).returncode,2);self.assertEqual((out/'report.json').read_bytes(),raw)
if __name__=='__main__':unittest.main()
