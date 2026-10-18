"""Generate illustrative records only. This script makes NO network requests."""
from pathlib import Path
from datetime import datetime,timezone,timedelta
import json
ROOT=Path(__file__).resolve().parents[1]
base=datetime(2026,10,1,0,0,0,tzinfo=timezone.utc)
scenarios={}
for name in ['normal','automation','scripted_scan','adaptive_illustration']:
 rows=[]
 for i in range(80):
  t=base+timedelta(seconds=i*(7 if name=='normal' else 2))
  method='GET';status=200;size=1200;auth=True
  if name=='normal':
   path=['/','/products','/products/100','/search?q=synthetic','/cart','/account/profile','/orders/101','/help'][i%8]
   if i in {12,49}:status=404
  elif name=='automation':
   path='/api/v1/items/'+str(1000+i);size=700
  elif name=='scripted_scan':
   path='/candidate-'+str(i);status=404;size=150;auth=False
  else:
   if i<20:path='/discovery-'+str(i);status=404;auth=False;size=150
   elif i<40:
    path=['/api/v1/items','/api/v2/items','/ops/reports','/account/profile'][i%4]
    status=[403,404,403,200][i%4];size=400
   elif i<60:
    method=['GET','POST','OPTIONS','GET'][i%4]
    path=['/api/v1/items','/api/v1/items','/api/v2/items','/api/v2/items'][i%4]
    status=[403,405,403,200][i%4];size=600
   else:
    path='/api/v2/items/'+str(2000+i);status=200;size=4000
  rows.append({'timestamp':t.isoformat(),'service_id':'lab-application',
   'actor_id':'synthetic-subject-01','client_ip':'192.0.2.10','method':method,
   'path':path,'status':status,'bytes_sent':size,'authenticated':auth})
 scenarios[name]=rows
 (ROOT/'examples').mkdir(exist_ok=True)
 (ROOT/'examples'/f'{name}.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows),encoding='utf-8')
meta={k:{'provenance':'programmatically_generated_illustration', 'records':len(v),
          'ai_agent_execution':False,'suitable_for_accuracy_claims':False} for k,v in scenarios.items()}
(ROOT/'examples/manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
tx={'timestamp':base.isoformat(),'service_id':'lab-application','transaction':{
 'time_stamp':base.isoformat(),'client_ip':'192.0.2.10',
 'request':{'method':'GET','uri':'/api/v1/items/1?token=EXAMPLE_NOT_A_SECRET'},
 'response':{'http_code':403},'messages':[]}}
(ROOT/'examples/modsecurity_v3_sample.jsonl').write_text(json.dumps(tx)+'\n')
print('Generated 4 x 80 synthetic records and one adapter fixture. No target traffic.')
