'use strict';
const $=id=>document.getElementById(id);
let current=null, customRows=null, engine='rules';
const label=x=>x.replaceAll('_',' ');
fetch('/api/info').then(r=>r.json()).then(info=>{
 engine=info.engine;
 $('mode').textContent=engine==='jev'?'JEV API MODE | External calls only after consent':'OFFLINE RULE BASELINE | No Jev inference | No network calls';
 $('consentrow').hidden=engine!=='jev';
}).catch(()=>{$('mode').textContent='Unable to read server mode';});
$('file').addEventListener('change',async()=>{
 try{
  const f=$('file').files[0]; if(!f){customRows=null;$('filelabel').textContent='';return;}
  if(f.size>1500000)throw Error('UI upload limit: 1.5 MB');
  customRows=(await f.text()).replace(/^\uFEFF/,'').split(/\r?\n/).filter(l=>l.trim()).map(l=>JSON.parse(l));
  $('filelabel').textContent=f.name+' | '+customRows.length+' records';$('error').hidden=true;
 }catch(e){customRows=null;$('filelabel').textContent='';showError(e.message);}
});
$('scenario').addEventListener('change',()=>{customRows=null;$('file').value='';$('filelabel').textContent='';});
function showError(s){$('error').hidden=false;$('error').textContent=s;}
$('run').addEventListener('click',async()=>{
 $('error').hidden=true;$('run').disabled=true;$('run').textContent='Analyzing...';
 try{
  const body={scenario:$('scenario').value,window:Number($('window').value),stride:Number($('stride').value),
    short_horizon:Number($('short').value),horizon:Number($('history').value)*60,consent:$('consent').checked};
  if(customRows)body.rows=customRows;
  const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name="demo-token"]').content},body:JSON.stringify(body)});
  const d=await r.json();if(!r.ok)throw Error(d.error||'Analysis failed');
  current=d;render();$('export').disabled=false;
 }catch(e){showError(e.message);}
 finally{$('run').disabled=false;$('run').textContent='Analyze sequence';}
});
function render(){
 const ws=current.windows;$('events').textContent=current.events.length;$('windows').textContent=ws.length;
 $('flags').textContent=ws.filter(w=>w.result.needs_review).length;$('engine').textContent=engine==='jev'?'Jev API':'Rule baseline';
 $('model').textContent=ws.length?ws[0].result.model:'No decisions';
 $('timeline').replaceChildren();
 ws.forEach((w,i)=>{const b=document.createElement('button');b.textContent=i+1;b.className=w.result.needs_review?'flag':'';b.title=w.state.as_of;b.addEventListener('click',()=>select(i));$('timeline').append(b);});
 if(ws.length)select(ws.length-1);
}
function select(i){
 const w=current.windows[i],s=w.state,r=w.result;
 [...$('timeline').children].forEach((x,j)=>x.classList.toggle('selected',i===j));
 $('selection').textContent=`Window ${i+1}/${current.windows.length} | ${s.window_count}/${s.window_limit} requests`;
 $('behavior').textContent=label(r.behavior);$('verdict').textContent=r.needs_review?'Analyst review flagged':'No review flag at this threshold';
 $('context').textContent=`${s.grouping} | recent ${s.short_horizon_seconds}s | history ${s.history_horizon_seconds/60}m | history records ${s.history_features.count}`+(s.cold_start?' | partial window':'')+(s.history_truncated?' | HISTORY TRUNCATED':'');
 $('score').textContent=r.score.toFixed(3);$('scorekind').textContent=label(r.score_kind)+'. '+r.notice;
 $('latency').textContent=engine==='jev'?`Measured API-call wall time: ${r.latency_ms} ms (including retries). Threshold: ${r.threshold}.`:`Rule threshold: ${r.threshold}. Not a probability or a calibrated attack score.`;
 const f=s.short_features;$('evidence').textContent=`Observed: ${f.changes_after_error} route/method changes after errors; ${f.unique_routes} route templates; ${f.unique_resources} distinct resource fingerprints. These counters are computed in Python, not supplied by Jev.`;
 $('rows').replaceChildren();s.recent_events.forEach(e=>{const tr=document.createElement('tr');[e.event_id,e.timestamp.slice(11,23),e.method,e.route,e.status,e.bytes_sent].forEach((v,j)=>{const td=document.createElement('td');td.textContent=String(v);if(j===3)td.className='route';tr.append(td);});$('rows').append(tr);});
 $('raw').textContent=JSON.stringify(w,null,2);
}
$('export').addEventListener('click',()=>{if(!current)return;const blob=new Blob([JSON.stringify(current,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='jevweb-analysis-'+engine+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);});
