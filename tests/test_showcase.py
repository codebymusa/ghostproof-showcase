"""Independent candidate expectations, never imported by inference.

Fake responses below are validation tests, not live model measurements.
"""
import builtins
import http.client
import io
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'code'))
from ghostproof.demo import run_demo
from ghostproof.dashboard import DashboardApp, DashboardServer
from ghostproof.local_extraction import ExtractionConfig, LocalExtractor, validate_proposals

EXPECTED = {'demo_river':('COMPLETE',8), 'demo_sky':('INCOMPLETE',9),
            'demo_ash':('INSUFFICIENT_EVIDENCE',2)}


class ShowcaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'reports'

    def run_cases(self, config=None):
        return run_demo(ROOT, output_dir=self.output, ai_config=config)[0]

    def test_offline_outcomes_and_independent_plan_constraints(self):
        report = self.run_cases()
        self.assertEqual({c['case_id']:(c['portfolio_status'],len(c['steps'])) for c in report['cases']}, EXPECTED)
        self.assertEqual(report['application_model_calls'],0)
        cases = {c['case_id']:c for c in report['cases']}
        complete = cases['demo_river']
        self.assertTrue(all(s['evidence_id'] and s['source_locations'] for s in complete['steps']))
        self.assertTrue(any(s['resource_id']=='tombstone_mira' and s['operation']=='VERIFY_RECORD_REDACTED'
                            for s in complete['steps']))
        steps = cases['demo_sky']['steps']
        self.assertEqual([s['operation'] for s in steps if s['phase']=='REMEDIATION'],['DISABLE_DATA_FLOW','DELETE_RECORD'])
        self.assertTrue(all(s['evidence_id']=='' for s in steps if s['phase']!='FINDING'))
        self.assertTrue(any(s['resource_id']=='profile_talin' and s['phase']=='VERIFICATION' for s in steps))
        ash = cases['demo_ash']; self.assertIsNone(ash['engine_status']); self.assertTrue(ash['review_reasons'])
        self.assertTrue(any(not f['eligible_at_audit'] for r in ash['resources'] for f in r['timeline']))

    def test_offline_never_reads_private_inputs_labels_or_cache_or_network(self):
        def guarded(opener):
            def call(path, *args, **kwargs):
                if not isinstance(path,int):
                    p=Path(path).resolve(); parts=p.parts
                    if (p.is_relative_to(ROOT/'dataset') or p.name in {'log.txt','sample_output.csv'}
                            or 'cache' in parts or p.is_relative_to(ROOT/'tests')):
                        raise AssertionError('Forbidden inference input')
                return opener(path,*args,**kwargs)
            return call
        with patch('builtins.open',guarded(builtins.open)), patch('io.open',guarded(io.open)), \
             patch.object(LocalExtractor,'request',side_effect=AssertionError('Offline model access')), \
             patch('socket.create_connection',side_effect=AssertionError('Offline network access')):
            self.assertEqual(self.run_cases()['application_model_calls'],0)

    def test_no_private_tree_or_benchmark_in_shell(self):
        for name in ('dataset','log.txt','agent-trace.zip','code.zip'):
            self.assertFalse((ROOT/name).exists(),name)
        shell=(ROOT/'code/dashboard/index.html').read_text(encoding='utf8')
        for text in ('2/4','4/4','9/9','23/32','Measured, small samples'):
            self.assertNotIn(text,shell)

    def test_cli_has_only_showcase_commands(self):
        result=subprocess.run([sys.executable,'-I','-B',str(ROOT/'code/main.py'),'--help'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0); self.assertIn('dashboard',result.stdout)
        for name in ('audit-dev','baseline','diagnostics','validate-output'):
            self.assertNotIn(name,result.stdout)

    def test_real_refused_ollama_connection_is_labelled_fallback_not_inference(self):
        # Bind without listening: keep the port reserved so no installed service
        # or unrelated process can be contacted while discovery is attempted.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0))
            config=ExtractionConfig(endpoint=f'http://127.0.0.1:{reserved.getsockname()[1]}',timeout=.5)
            report=self.run_cases(config)
        run=report['extraction_runs'][0]
        self.assertTrue(run['fallback_used']); self.assertFalse(run['cache_hit'])
        self.assertEqual(run['error_type'],'URLError'); self.assertEqual(run['discovery_requests'],1)
        self.assertEqual(run['provider'],'offline'); self.assertEqual(run['model_calls'],0)
        self.assertIsNone(run['input_tokens']); self.assertIsNone(run['output_tokens'])
        self.assertEqual(run['accepted_facts'],2)
        self.assertEqual(next(c for c in report['cases'] if c['case_id']=='demo_ash')['portfolio_status'],'COMPLETE')

    def test_explicit_offline_note_provider_is_not_model_success(self):
        with patch.object(LocalExtractor,'request',side_effect=AssertionError('No model for offline provider')):
            report=self.run_cases(ExtractionConfig(provider='offline'))
        run=report['extraction_runs'][0]
        self.assertTrue(run['fallback_used']); self.assertEqual(run['fallback_reason'],'offline_provider_selected')
        self.assertEqual(run['model_calls'],0); self.assertIsNone(run['model'])

    def test_fake_valid_model_selection_uses_the_same_grounding(self):
        def fake(client,path,data=None,timeout=None):
            client.cache_dir=None  # Never persist a fake generation in the candidate.
            if path=='/api/tags':
                return {'models':[{'name':client.config.model,'size':1,'digest':'fake-test-only'}]}
            return {'model':client.config.model,'done':True,'response':json.dumps({
                'facts':[{'line_no':2},{'line_no':3}],'uncertainties':[]}),
                'prompt_eval_count':10,'eval_count':5}
        with patch.object(LocalExtractor,'request',fake): report=self.run_cases(ExtractionConfig())
        run=report['extraction_runs'][0]
        self.assertFalse(run['fallback_used']); self.assertEqual(run['accepted_facts'],2)
        self.assertEqual(run['provider'],'ollama')

    def test_fake_malformed_model_reply_is_labelled_fallback(self):
        def fake(client,path,data=None,timeout=None):
            client.cache_dir=None
            if path=='/api/tags': return {'models':[{'name':client.config.model,'size':1,'digest':'fake-test-only'}]}
            return {'model':client.config.model,'done':True,'response':'not json'}
        with patch.object(LocalExtractor,'request',fake): report=self.run_cases(ExtractionConfig())
        self.assertTrue(report['extraction_runs'][0]['fallback_used'])

    def test_unsupported_resource_citation_is_rejected(self):
        text='At 2026-01-09T13:00:00Z, the search_service primary readback for search_example and subject user_example found no record.'
        facts,validation=validate_proposals({'facts':[{'line_no':1,'resource_id':'invented_record',
            'observation':'presence','value':'ABSENT'}],'uncertainties':[]},text,
            {'file_id':'fictional_test','file_path':'test.txt','captured_at':'2026-01-09T14:00:00Z'},method='ollama',model='fake')
        self.assertEqual(facts,[]); self.assertTrue(validation['rejected'])

    def test_visual_coverage_is_explicitly_pending_not_absence(self):
        from ghostproof.visual_evidence import parse_visual
        facts,issues,status=parse_visual(Path('fictional.pdf'),{'file_id':'unsupported_visual'})
        self.assertEqual(facts,[]);self.assertTrue(issues);self.assertEqual(status,'PENDING')

    def test_http_offline_cases_and_backend_ai_guard(self):
        server=DashboardServer(DashboardApp(ROOT,ai_enabled=False),0)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            self.assertEqual(server.server_address[0],'127.0.0.1')
            for case,(status,_) in EXPECTED.items():
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                conn.request('POST','/api/audit',json.dumps({'case_id':case,'mode':'offline'}),{'Content-Type':'application/json'})
                response=conn.getresponse();self.assertEqual(response.status,200)
                self.assertEqual(json.load(response)['case']['portfolio_status'],status);conn.close()
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            conn.request('POST','/api/audit',json.dumps({'case_id':'demo_ash','mode':'ai'}),{'Content-Type':'application/json'})
            response=conn.getresponse();self.assertEqual(response.status,400);response.read();conn.close()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)


if __name__=='__main__': unittest.main()
