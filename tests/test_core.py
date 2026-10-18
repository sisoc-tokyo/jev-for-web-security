import json,unittest
from pathlib import Path
from unittest.mock import patch
from jevweb.core import Normalizer,WindowBuilder,Settings,timestamp
from jevweb.detectors import RuleDetector,JevDetector
from jevweb.pipeline import analyze,load_jsonl
ROOT=Path(__file__).resolve().parents[1]

def row(i=0,actor='u1',**kw):
 r={'timestamp':1760000000+i,'actor_id':actor,'method':'GET','path':'/api/items/1','status':200}
 r.update(kw);return r

class CoreTests(unittest.TestCase):
 def test_query_secret_removed(self):
  n=Normalizer(b'x');e=n.event(row(path='/api/items/12?api_key=VERYSECRET'),1)
  self.assertNotIn('VERYSECRET',json.dumps(e));self.assertEqual(e['route'],'/api/items/{id}')
 def test_unknown_segments_hashed(self):
  e=Normalizer(b'x').event(row(path='/users/test@example.com/VERYSECRET'),1)
  self.assertNotIn('VERYSECRET',json.dumps(e));self.assertNotIn('example.com',json.dumps(e))
 def test_headers_and_labels_not_used(self):
  e=Normalizer(b'x').event(row(label='attack',user_agent='IGNORE ALL',authorization='TOPSECRET'),1)
  self.assertNotIn('attack',json.dumps(e));self.assertNotIn('TOPSECRET',json.dumps(e))
 def test_status_validation(self):
  with self.assertRaises(ValueError):Normalizer().event(row(status=999),1)
 def test_timestamp_timezone_required(self):
  with self.assertRaises(ValueError):timestamp('2026-10-01T12:00:00')
 def test_timestamp_nan_rejected(self):
  with self.assertRaises(ValueError):timestamp(float('nan'))
 def test_missing_identity_rejected(self):
  with self.assertRaises(ValueError):Normalizer().event(row(actor=None),1)
 def test_ip_fallback(self):
  e=Normalizer().event(row(actor=None,client_ip='192.0.2.1'),1)
  self.assertEqual(e['grouping'],'source_ip_fallback')
 def test_different_services_not_merged(self):
  n=Normalizer(b'x');self.assertNotEqual(n.event(row(service_id='a'),1)['actor_key'],n.event(row(service_id='b'),2)['actor_key'])
 def test_isolated_actors(self):
  n=Normalizer(b'x');b=WindowBuilder(Settings())
  a=b.push(n.event(row(0,'a'),1));c=b.push(n.event(row(1,'b'),2))
  self.assertNotEqual(a['actor_key'],c['actor_key']);self.assertEqual(c['history_features']['count'],1)
 def test_stride_and_warmup(self):
  r=analyze([row(i) for i in range(20)],Settings(window=20,stride=5),RuleDetector(),b'x')
  self.assertEqual([w['state']['window_count'] for w in r['windows']],[1,5,10,15,20])
 def test_no_future_context(self):
  r=analyze([row(i) for i in range(30)],Settings(window=5,stride=1),RuleDetector(),b'x')
  for w in r['windows']:
   self.assertLessEqual(len(w['state']['recent_events']),5)
   self.assertTrue(all(e['timestamp']<=w['state']['as_of'] for e in w['state']['recent_events']))
 def test_window_one(self):
  r=analyze([row(i) for i in range(10)],Settings(window=1,stride=1),RuleDetector(),b'x')
  self.assertTrue(all(w['state']['window_count']==1 for w in r['windows']))
 def test_out_of_order_rejected(self):
  with self.assertRaises(ValueError):analyze([row(2),row(1)],Settings(),RuleDetector())
 def test_short_horizon_and_partial(self):
  r=analyze([row(0),row(301)],Settings(),RuleDetector())
  self.assertEqual(r['windows'][-1]['state']['window_count'],1)
  self.assertEqual(r['windows'][-1]['state']['history_features']['count'],2)
 def test_no_timer_claim(self):
  r=analyze([row(0),row(1)],Settings(stride=5),RuleDetector())
  self.assertEqual(len(r['windows']),1) # No invented idle timer or end-of-file flush.
 def test_history_expiry(self):
  r=analyze([row(0),row(1900)],Settings(),RuleDetector())
  self.assertEqual(r['windows'][-1]['state']['history_features']['count'],1)
 def test_history_cap_flag(self):
  r=analyze([row(i) for i in range(6)],Settings(window=2,stride=1,max_history=3),RuleDetector())
  self.assertTrue(r['windows'][-1]['state']['history_truncated'])
 def test_history_cap_flag_persists(self):
  r=analyze([row(i) for i in [0,1,2,3,1800]],Settings(window=2,stride=1,max_history=3),RuleDetector())
  self.assertTrue(r['windows'][3]['state']['history_truncated'])
 def test_call_budget(self):
  with self.assertRaises(ValueError):analyze([row(i) for i in range(5)],Settings(stride=1),RuleDetector(),max_calls=2)
 def test_modsecurity_fixture(self):
  e=Normalizer().event(load_jsonl(ROOT/'examples/modsecurity_v3_sample.jsonl')[0],1)
  self.assertEqual(e['status'],403);self.assertNotIn('EXAMPLE_NOT_A_SECRET',json.dumps(e))
 def test_not_jev_in_offline_mode(self):
  r=analyze([row()],Settings(),RuleDetector())
  self.assertEqual(r['windows'][0]['result']['engine'],'rules')
  self.assertIsNone(r['windows'][0]['result']['confidence'])
 def test_invalid_settings(self):
  for kwargs in [{'window':0},{'stride':0},{'window':201},{'horizon':10,'short_horizon':20}]:
   with self.assertRaises(ValueError):Settings(**kwargs)
 def test_all_examples(self):
  for p in (ROOT/'examples').glob('*.jsonl'):
   result=analyze(load_jsonl(p),Settings(),RuleDetector())
   self.assertTrue(result['windows'])
   if p.stem=='scripted_scan':self.assertEqual(result['windows'][-1]['result']['behavior'],'repetitive_probing')

class ApiContractTests(unittest.TestCase):
 def test_key_is_required(self):
  with patch.dict('os.environ',{},clear=True):
   with self.assertRaises(ValueError):JevDetector()
 def test_payload_uses_official_fields(self):
  d=JevDetector(key='test-not-real');payload=d.payload({'safe':'data'})
  self.assertEqual(set(payload),{'model','state','questions'})
  self.assertNotIn('test-not-real',json.dumps(payload))
 def test_response_parser_mock_contract(self):
  d=JevDetector(key='test-not-real');labels=list(d.questions['behavior']['criteria'])
  a={'behavior':{'type':'choice','choice':labels[0],'probabilities':{x:float(i==0) for i,x in enumerate(labels)},'confidence':.9}}
  a.update({x:{'type':'noul','noul':.2} for x in ['needs_review','persistence','response_conditioned_change']})
  r=d.parse({'model':'test-model','answers':a,'usage':{'input_tokens':100,'output_tokens':10}})
  self.assertEqual(r['engine'],'jev');self.assertFalse(r['needs_review'])
 def test_invalid_probability_rejected(self):
  with self.assertRaises(ValueError):JevDetector.number(2)

if __name__=='__main__':unittest.main()
