from __future__ import annotations
import hashlib, json, time
from .core import Normalizer,Settings,WindowBuilder

def analyze(rows:list[dict],settings:Settings,detector, salt:bytes|None=None,max_calls:int=1000)->dict:
    if len(rows)>50000: raise ValueError('Prototype limit: 50000 events per replay')
    if not rows: raise ValueError('No events found')
    normalizer=Normalizer(salt);builder=WindowBuilder(settings)
    events=[];windows=[]
    start=time.perf_counter()
    for seq,row in enumerate(rows,1):
        e=normalizer.event(row,seq);events.append(e)
        state=builder.push(e)
        if state is not None:
            if len(windows)>=max_calls:
                raise ValueError(f'Inference call limit ({max_calls}) exceeded. Increase stride or split input.')
            result=detector.evaluate(state)
            windows.append({'state':state,'result':result})
    return {'tool':'Jev for Web Security','version':'0.1.0','settings':vars(settings),
            'events':events,'windows':windows,
            'elapsed_ms':round((time.perf_counter()-start)*1000,2),
            'disclaimer':'Behavior hypotheses only. Source-IP grouping is not a user identity. Synthetic samples are not benchmark evidence.'}

def load_jsonl(path):
    rows=[]
    with open(path,encoding='utf-8-sig') as f:
        for i,line in enumerate(f,1):
            if not line.strip():continue
            try: rows.append(json.loads(line))
            except json.JSONDecodeError as exc: raise ValueError(f'Invalid JSON on line {i}') from exc
    return rows
