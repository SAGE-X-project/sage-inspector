"""Safe provenance/process controls; all mutated output stays in memory/temp data."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import core_key_authority_observation as o
import core_key_authority_execution as x
from test_core_key_authority_observation import rows


class CoreExecutionTests(unittest.TestCase):
    def test_public_graph_no_replacements_and_stream_duplicates(self):
        raw=b'{"Path":"main","Main":true}\n{"Path":"public","Version":"v1","Sum":"h1:x"}\n'
        self.assertEqual(len(x.modules(raw)),2)
        self.assertEqual(len(x.public_graph(raw,{'public':{'Version':'v1','Sum':'h1:x'}})),2)
        with self.assertRaises(ValueError):x.public_graph(raw,{'public':{'Version':'v2'}})
        for raw in [b'{"Path":"one","Path":"two"}',b'{"Path":"one"}{"Path":"one"}',b'{"Path":"one","Replace":{}}',b'{"Path":"one","Sum":NaN}',b'{}',b'[]']:
            with self.assertRaises(ValueError):x.modules(raw)

    def test_compiler_race_unique_typed_optional_build_settings(self):
        good={'GoVersion':'go1.26.8','Path':o.PACKAGE+'.test','Settings':[{'Key':'-race','Value':'true'},{'Key':'CGO_CFLAGS'}]}
        x.go_identity(good)
        for mode in ['compiler','path','missing-race','false-race','duplicate','key-type','value-type','extra']:
            bad=copy.deepcopy(good)
            if mode=='compiler':bad['GoVersion']='go1.26.9'
            elif mode=='path':bad['Path']='other'
            elif mode=='missing-race':bad['Settings'].pop(0)
            elif mode=='false-race':bad['Settings'][0]['Value']='false'
            elif mode=='duplicate':bad['Settings'].append(copy.deepcopy(bad['Settings'][0]))
            elif mode=='key-type':bad['Settings'][0]['Key']=False
            elif mode=='value-type':bad['Settings'][0]['Value']=True
            else:bad['Settings'][0]['extra']='ignored'
            with self.subTest(mode=mode),self.assertRaises(ValueError):x.go_identity(bad)

    def test_rust_executable_selection_rejects_escape_duplicate_wrong_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'target';binary=target/'debug/deps/owned';target.mkdir()
            good={'reason':'compiler-artifact','target':{'name':'sage_crypto_core'},'profile':{'test':True},'executable':str(binary)}
            self.assertEqual(x.rust_binary((json.dumps(good)+'\n').encode(),target),binary)
            for changed in [{**good,'executable':str(target/'../outside')},{**good,'executable':'relative'},{**good,'target':{'name':'other'}},{**good,'profile':{'test':1}}]:
                with self.assertRaises(ValueError):x.rust_binary(json.dumps(changed).encode(),target)
            with self.assertRaises(ValueError):x.rust_binary((json.dumps(good)+'\n'+json.dumps(good)).encode(),target)
            with self.assertRaises(ValueError):x.rust_binary(b'{"reason":"build-finished"}',target)
            binary.parent.mkdir(parents=True);binary.symlink_to('/dev/null')
            with self.assertRaises(ValueError):x.rust_binary(json.dumps(good).encode(),target)

    def test_exclusive_files_whole_tree_and_selected_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);x.save(root,'owned',b'content');expected={'owned':o.sha(b'content')}
            self.assertEqual(x.file_tree(root),expected);self.assertEqual(x.selected_sources(root,expected),expected)
            with self.assertRaises(FileExistsError):x.save(root,'owned',b'replace')
            with self.assertRaises(ValueError):x.selected_sources(root,{'owned':'0'*64})
            (root/'.git').mkdir();(root/'.git/config').write_bytes(b'private local metadata')
            self.assertEqual(x.file_tree(root,True),expected)
            (root/'link').symlink_to(root/'owned')
            with self.assertRaises(ValueError):x.file_tree(root)
            with self.assertRaises(ValueError):x.save(root,'link',b'data')

    def test_whole_source_pins_and_independent_go_hash1(self):
        selected=o.subject()['go'];whole=selected['whole_sources'];x.module_identity(whole,selected['module'])
        for field,value in [('Sum','h1:wrong'),('GoModSum','h1:wrong'),('Version','v0.0.0')]:
            bad=dict(selected['module']);bad[field]=value
            with self.assertRaises(ValueError):x.module_identity(whole,bad)
        changed=dict(whole);unselected=next(p for p in whole if p not in selected['sources']);changed[unselected]='0'*64
        with self.assertRaises(ValueError):x.module_identity(changed,selected['module'])
        with self.assertRaises(ValueError):x.hash1({'newline\npath':'0'*64})
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'selected').write_bytes(b'a');(root/'unselected').write_bytes(b'b');expected=x.file_tree(root)
            self.assertEqual(x.full_sources(root,expected),expected)
            (root/'unselected').write_bytes(b'changed')
            with self.assertRaises(ValueError):x.full_sources(root,expected)

    def test_failed_process_and_timeout_keep_available_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);trace=[]
            done=subprocess.CompletedProcess(['fixed'],0,b'ok',b'')
            with patch.object(x.subprocess,'run',return_value=done):self.assertEqual(x.command(['fixed'],directory,{},directory,'good',trace),b'ok')
            self.assertEqual(trace[0]['returncode'],0)
            done=subprocess.CompletedProcess(['fixed'],2,b'failed stdout',b'failed stderr')
            with patch.object(x.subprocess,'run',return_value=done),self.assertRaises(ValueError):x.command(['fixed'],directory,{},directory,'failed',trace)
            self.assertEqual((directory/'failed.stdout').read_bytes(),b'failed stdout')
            error=subprocess.TimeoutExpired(['fixed'],1,output=b'partial',stderr=b'timeout')
            with patch.object(x.subprocess,'run',side_effect=error),self.assertRaises(ValueError):x.command(['fixed'],directory,{},directory,'timeout',trace)
            self.assertEqual((directory/'timeout.stdout').read_bytes(),b'partial')

    def test_environment_and_mocked_launch_are_not_native_evidence(self):
        with patch.dict(os.environ,{'RUSTFLAGS':'unsafe','RUSTC_WRAPPER':'wrapper'}):
            env=x.environment();self.assertNotIn('RUSTFLAGS',env);self.assertNotIn('RUSTC_WRAPPER',env);self.assertEqual(env['GOPROXY'],'off')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            with patch.object(x,'go_execute',return_value=(rows('go'),{'synthetic':True})),patch.object(x,'rust_execute',return_value=(rows('rust'),{'synthetic':True})),patch.object(x.subprocess,'check_output',return_value='a'*40+'\n'):
                report=x.run_native(directory,directory)
            self.assertEqual(report['status_counts'],{'PARTIAL':2,'NOT_RUN':581});self.assertTrue(report['execution']['go']['synthetic'])
            with self.assertRaises(FileExistsError):x.save(directory,'core-key-authority-native.json',b'bad')
            with patch.object(x,'go_execute',return_value=(rows('go'),{})),patch.object(x,'rust_execute',return_value=(rows('rust'),{})),patch.object(x.subprocess,'check_output',return_value='a'*40+'\n'),patch.object(o,'observer_sources',side_effect=[{'one':'first'},{'one':'changed'}]),self.assertRaises(ValueError):x.run_native(directory,directory)


class NativeReportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value=os.environ.get('CORE_KEY_AUTHORITY_EVIDENCE')
        if value is None:raise unittest.SkipTest('requires the separately generated native CI artifact; no execution is invented')
        cls.source=Path(value)

    def test_actual_report_and_proof_tamper_controls(self):
        import check_core_key_authority_evidence as checker
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'copied';shutil.copytree(self.source,directory)
            with contextlib.redirect_stdout(io.StringIO()):original=checker.verify(directory)
            path=directory/'core-key-authority-native.json'
            mutations=[('kind','other'),('evidence_kind','reported-output'),('status_counts',{'PARTIAL':2,'NOT_RUN':580}),('historical_results_merged',True),('extra','PASS')]
            for key,value in mutations:
                bad=copy.deepcopy(original);bad[key]=value;path.write_text(json.dumps(bad))
                with self.subTest(field=key),self.assertRaises(ValueError):checker.verify(directory)
            for lang,key,value in [('go','download',{}),('go','selected_sources',{}),('go','build_info',{}),('go','raw_test_sha256','0'*64),('go','whole_source_sha256','0'*64),('go','whole_source_files',True),('rust','cargo_lock_sha256','0'*64),('rust','revision','b'*40),('rust','compiler','rustc other'),('rust','test_executable','/outside/target'),('rust','selected_sources',{})]:
                bad=copy.deepcopy(original);bad['execution'][lang][key]=value;path.write_text(json.dumps(bad))
                with self.subTest(lang=lang,key=key),self.assertRaises((ValueError,KeyError)):checker.verify(directory)
            for mode in ['args','cwd','returncode','output-hash','environment','observer','missing-command','capture-directory','raw-bool-counter']:
                bad=copy.deepcopy(original)
                if mode=='args':bad['execution']['commands'][5]['args'].remove('-race')
                elif mode=='cwd':bad['execution']['commands'][5]['cwd']='/outside'
                elif mode=='returncode':bad['execution']['commands'][0]['returncode']=False
                elif mode=='output-hash':bad['execution']['commands'][0]['stdout_sha256']='0'*64
                elif mode=='environment':bad['execution']['environment']['GOPROXY']='direct'
                elif mode=='observer':bad['observer']['revision']='c'*40
                elif mode=='missing-command':bad['execution']['commands'].pop()
                elif mode=='capture-directory':bad['execution']['capture_directory']='relative'
                else:bad['go_observations']['normal']['application_request_opened']=True
                path.write_text(json.dumps(bad))
                with self.subTest(mode=mode),self.assertRaises((ValueError,KeyError)):checker.verify(directory)
            path.write_text(json.dumps(original))
            for name in ['go-tests.stdout','rust-tests.stdout','rust-Cargo.lock','go-whole-sources.json','rust-whole-sources.json']:
                target=directory/name;raw=target.read_bytes();target.write_bytes(raw+b'changed')
                with self.subTest(raw=name),self.assertRaises((ValueError,KeyError)):checker.verify(directory)
                target.write_bytes(raw)
            with contextlib.redirect_stdout(io.StringIO()):checker.verify(directory)


if __name__ == '__main__':unittest.main()
