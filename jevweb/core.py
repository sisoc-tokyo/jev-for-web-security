"""Causal, per-entity windows. No ML labels or raw credentials reach a detector."""
from __future__ import annotations
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib, hmac, ipaddress, math, re, secrets
from urllib.parse import urlsplit, unquote
from typing import Any

@dataclass(frozen=True)
class Settings:
    window: int = 20
    stride: int = 5
    horizon: int = 1800
    short_horizon: int = 300
    max_history: int = 10000
    max_actors: int = 1000
    def __post_init__(self):
        for name in ('window','stride','horizon','short_horizon','max_history','max_actors'):
            v=getattr(self,name)
            if type(v) is not int or v < 1:
                raise ValueError(f'{name} must be a positive integer')
        if self.window > 200 or self.stride > 200:
            raise ValueError('Prototype limit: window and stride <= 200')
        if self.short_horizon > self.horizon or self.window > self.max_history:
            raise ValueError('short_horizon <= horizon and window <= max_history required')
        if self.horizon > 86400:
            raise ValueError('Prototype limit: horizon <= 86400 seconds')

def timestamp(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError('Invalid timestamp')
    if isinstance(value, (int,float)):
        t=float(value)
    elif isinstance(value,str):
        try:
            d=datetime.fromisoformat(value.replace('Z','+00:00'))
            if d.tzinfo is None:
                raise ValueError('Timestamp must include timezone')
        except ValueError as exc:
            # ModSecurity v3 commonly uses this date representation.
            try:
                d=datetime.strptime(value,'%a %b %d %H:%M:%S %Y')
                raise ValueError('Timezone-free ModSecurity time: export a UTC timestamp field') from exc
            except ValueError:
                raise ValueError('Use a UNIX timestamp or ISO-8601 timestamp with timezone') from exc
        t=d.timestamp()
    else:
        raise ValueError('timestamp is required')
    if not math.isfinite(t) or t < 0:
        raise ValueError('Invalid timestamp')
    return t

def iso(t: float) -> str:
    return datetime.fromtimestamp(t,timezone.utc).isoformat(timespec='milliseconds')

class Normalizer:
    """Allow-list fields; keys are local trusted log fields, not HTTP headers."""
    def __init__(self, salt: bytes | None=None):
        self.salt=salt or secrets.token_bytes(32)
    def digest(self,value: str)->str:
        return hmac.new(self.salt,value.encode('utf-8'),hashlib.sha256).hexdigest()[:16]
    def event(self, row: dict, seq: int) -> dict:
        if not isinstance(row,dict):
            raise ValueError('Each log record must be an object')
        tx=row.get('transaction')
        if isinstance(tx,dict):
            req=tx.get('request',{})
            res=tx.get('response',{})
            # Supported shape: ModSecurity v3 JSON with nested request/response.
            row={'timestamp':row.get('timestamp',tx.get('time_stamp')),
                 'client_ip':tx.get('client_ip'),'method':req.get('method'),
                 'path':req.get('uri'), 'status':res.get('http_code'),
                 'bytes_sent':row.get('bytes_sent',0),
                 'service_id':row.get('service_id','default'),
                 'actor_id':row.get('actor_id'),
                 'authenticated':row.get('authenticated'),
                 'waf_alerts':len(tx.get('messages',[]))}
        t=timestamp(row.get('timestamp',row.get('ts')))
        method=str(row.get('method','GET')).upper()
        if method not in {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','PROPFIND'}:
            method='OTHER'
        try:
            status=int(row.get('status'))
            size=int(row.get('bytes_sent',0))
            alerts=int(row.get('waf_alerts',0))
        except (ValueError,TypeError):
            raise ValueError('status, bytes_sent and waf_alerts must be integers')
        if not 100<=status<=599 or size<0 or alerts<0:
            raise ValueError('Invalid status, size or alert count')
        raw=str(row.get('path',row.get('uri','/')))[:4096]
        try:
            path=unquote(urlsplit(raw).path or '/')
        except ValueError:
            raise ValueError('Invalid request URI')
        # Never pass raw path segments or query strings. These may carry PII,
        # API keys, arbitrary instructions or embedded attack payloads.
        segments=[]
        for segment in path.strip('/').split('/')[:16]:
            if not segment: continue
            if re.fullmatch(r'\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}',segment):
                segments.append('{id}')
            elif re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,39}',segment):
                # Only generic route words are retained; unknown names hashed.
                known={'api','v1','v2','v3','items','item','orders','order','users','user',
                       'account','accounts','profile','login','logout','auth','search',
                       'products','product','cart','checkout','health','status','admin',
                       'ops','export','reports','report','documents','document','help',
                       'contact','password','reset','assets','static','catalog','me',
                       'settings','session','sessions','list','detail','home','index.html'}
                segments.append(segment.lower() if segment.lower() in known else 'p_'+self.digest(segment)[:8])
            else:
                segments.append('p_'+self.digest(segment)[:8])
        route='/'+'/'.join(segments)
        resource_fp=self.digest(path)  # Helps count targets without disclosing identifiers.
        service=self.digest(str(row.get('service_id','default')))
        actor=row.get('actor_id')
        if actor is not None and str(actor):
            identity='trusted:'+str(actor)
            grouping='trusted_actor_id'
        else:
            ip=row.get('client_ip',row.get('remote_addr'))
            try: ip=ipaddress.ip_address(str(ip)).compressed
            except ValueError: raise ValueError('A trusted actor_id or valid client_ip is required')
            identity='ip:'+ip
            grouping='source_ip_fallback'
        return {'t':t,'timestamp':iso(t),'event_id':f'e{seq:06d}',
                'actor_key':self.digest(service+':'+identity),'grouping':grouping,
                'method':method,'route':route,'resource_fp':resource_fp,
                'status':status,'bytes_sent':size,'waf_alerts':alerts,
                'authenticated':row.get('authenticated') if isinstance(row.get('authenticated'),bool) else None}

def features(events: list[dict]) -> dict:
    n=len(events)
    codes=Counter(str(e['status']) for e in events)
    failures=sum(e['status']>=400 for e in events)
    transitions=[]
    for a,b in zip(events,events[1:]):
        changed=(a['route'],a['method'])!=(b['route'],b['method'])
        if a['status']>=400 and changed:
            transitions.append({'from_event':a['event_id'],'to_event':b['event_id'],
                                'from_status':a['status'],'to_status':b['status']})
    duration=events[-1]['t']-events[0]['t'] if n>1 else 0
    return {'count':n,'duration_seconds':round(duration,3),
            'status_counts':dict(codes),'error_fraction':round(failures/n,4) if n else 0,
            'unique_routes':len({e['route'] for e in events}),
            'unique_resources':len({e['resource_fp'] for e in events}),
            'route_or_method_changes':sum((a['route'],a['method'])!=(b['route'],b['method']) for a,b in zip(events,events[1:])),
            'changes_after_error':len(transitions),
            'successful_responses':sum(200<=e['status']<300 for e in events),
            'bytes_sent':sum(e['bytes_sent'] for e in events),
            'waf_alert_count':sum(e['waf_alerts'] for e in events),
            'mean_requests_per_second':round((n-1)/duration,4) if duration>0 else None,
            'transition_evidence':transitions[-8:]}

class WindowBuilder:
    def __init__(self, settings: Settings):
        self.s=settings
        self.actors={}
        self.last_time=-1.0
    def push(self,e:dict)->dict|None:
        if e['t']<self.last_time:
            raise ValueError('Records must be in timestamp order; sort upstream, not using future context')
        self.last_time=e['t']
        # Inactive identities expire; avoid indefinite per-IP state retention.
        for k in [k for k,v in self.actors.items() if e['t']-v['last']>self.s.horizon]:
            del self.actors[k]
        key=e['actor_key']
        if key not in self.actors:
            if len(self.actors)>=self.s.max_actors:
                raise ValueError('max_actors exceeded; partition this replay')
            self.actors[key]={'events':deque(),'seen':0,'last':e['t'],
                              'evaluated_at':None,'truncated_until':-1.0}
        a=self.actors[key];a['last']=e['t'];a['seen']+=1
        q=a['events'];q.append(e)
        while q and e['t']-q[0]['t']>self.s.horizon: q.popleft()
        while len(q)>self.s.max_history:
            dropped=q.popleft();a['truncated_until']=max(a['truncated_until'],dropped['t']+self.s.horizon)
        due=(a['seen']==1 or a['seen']%self.s.stride==0 or
             (a['evaluated_at'] is not None and e['t']-a['evaluated_at']>=self.s.short_horizon))
        if not due: return None
        a['evaluated_at']=e['t']
        all_events=list(q)
        short=[v for v in all_events if e['t']-v['t']<=self.s.short_horizon][-self.s.window:]
        long=features(all_events)
        long.pop('transition_evidence',None)
        return {'schema_version':'1.0','as_of':e['timestamp'],'actor_key':key,
                'grouping':e['grouping'],'window_limit':self.s.window,
                'window_count':len(short),'short_horizon_seconds':self.s.short_horizon,
                'history_horizon_seconds':self.s.horizon,
                'history_truncated':e['t']<=a['truncated_until'],
                'cold_start':len(short)<self.s.window,
                'short_features':features(short),'history_features':long,
                'recent_events':[{k:v for k,v in x.items() if k not in {'actor_key','grouping','t'}} for x in short]}
