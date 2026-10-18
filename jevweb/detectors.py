"""Transparent offline baseline and a real, explicitly selected Jev HTTP client."""
from __future__ import annotations
import json, math, os, time, urllib.request, urllib.error
from pathlib import Path
QUESTIONS=Path(__file__).resolve().parents[1]/'config/questions.json'
ENDPOINT='https://api.typesafe.ai/v1/systemone'

class RuleDetector:
    def evaluate(self,state:dict)->dict:
        f=state['short_features']; n=f['count']
        # Deliberately simple, disclosed baseline. NOT an AI model and NOT a probability.
        score=round(min(1.0,0.5*f['error_fraction'] +
                        0.3*min(f['changes_after_error']/5,1) +
                        0.2*min(f['unique_routes']/12,1)),3)
        if n<5: label='insufficient_evidence'
        elif f['error_fraction']>=.9: label='repetitive_probing'
        elif f['error_fraction']>=.2 and f['changes_after_error']>=3: label='changing_strategy'
        elif f['error_fraction']>=.5: label='repetitive_probing'
        elif f['unique_routes']<=3 and n>=10: label='regular_automation'
        else: label='ordinary_activity'
        return {'engine':'rules','model':'transparent-baseline-v1','behavior':label,
                'score':score,'score_kind':'heuristic_not_probability',
                'confidence':None,'probabilities':None,
                'needs_review':bool(score>=.65 and n>=5),'threshold':.65,
                'latency_ms':0.0,'usage':None,
                'notice':'Offline rule baseline. This is not a Jev prediction.'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise RuntimeError('API redirects are refused to protect the Bearer token')

class JevDetector:
    def __init__(self,key:str|None=None,model:str='jev-1.14.0',timeout:float=30.0,threshold:float=.8):
        self.key=key or os.environ.get('TYPESAFE_API_KEY','')
        if not self.key: raise ValueError('Set TYPESAFE_API_KEY locally, or start with --ask-key. No key is included.')
        if not 0<=threshold<=1: raise ValueError('threshold must be between 0 and 1')
        self.model=model;self.timeout=timeout;self.threshold=threshold
        self.questions=json.loads(QUESTIONS.read_text(encoding='utf-8'))
        self.opener=urllib.request.build_opener(NoRedirect())
    def payload(self,state:dict)->dict:
        return {'model':self.model,'state':state,'questions':self.questions}
    @staticmethod
    def number(x):
        v=float(x)
        if not math.isfinite(v) or not 0<=v<=1: raise ValueError('Invalid probability in API response')
        return v
    def parse(self,data:dict)->dict:
        a=data['answers'];b=a['behavior']; p=self.number(a['needs_review']['noul'])
        labels=set(self.questions['behavior']['criteria'])
        if b.get('type')!='choice' or b['choice'] not in labels:
            raise ValueError('Unexpected behavior answer')
        if set(b['probabilities'])!=labels: raise ValueError('Incomplete probability map')
        probs={k:self.number(v) for k,v in b['probabilities'].items()}
        if abs(sum(probs.values())-1)>.02: raise ValueError('Probabilities do not sum to one')
        return {'engine':'jev','model':str(data['model']), 'behavior':b['choice'],
                'score':p,'score_kind':'model_output_not_calibrated_for_this_task',
                'confidence':self.number(b['confidence']),'probabilities':probs,
                'needs_review':p>=self.threshold,'threshold':self.threshold,
                'persistence':self.number(a['persistence']['noul']),
                'response_conditioned_change':self.number(a['response_conditioned_change']['noul']),
                'usage':data.get('usage'),
                'notice':'Model assessment, not proof of malicious intent, AI attribution or a data breach.'}
    def evaluate(self,state:dict)->dict:
        body=json.dumps(self.payload(state),ensure_ascii=True,allow_nan=False).encode()
        if len(body)>256000: raise ValueError('Local safety cap: model payload exceeds 256000 bytes')
        start=time.perf_counter()
        for attempt in range(3):
            req=urllib.request.Request(ENDPOINT,data=body,headers={
                'Authorization':'Bearer '+self.key,'Content-Type':'application/json'},method='POST')
            try:
                with self.opener.open(req,timeout=self.timeout) as res:
                    data=json.loads(res.read(2000000))
                result=self.parse(data)
                result['latency_ms']=round((time.perf_counter()-start)*1000,2)
                return result
            except urllib.error.HTTPError as exc:
                if exc.code in {429,500,502,503,504,529} and attempt<2:
                    try: wait=min(5,max(0,float(exc.headers.get('Retry-After',2**attempt))))
                    except (TypeError,ValueError): wait=2**attempt
                    time.sleep(wait);continue
                raise RuntimeError(f'Jev HTTP {exc.code}. No fallback prediction was substituted.') from None
            except (KeyError,TypeError,ValueError) as exc:
                raise RuntimeError('Jev response did not match the documented schema; no verdict returned.') from exc
            except urllib.error.URLError:
                raise RuntimeError('Jev network failure; no verdict returned.') from None
        raise RuntimeError('Jev request failed')
