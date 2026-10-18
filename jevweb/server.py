"""Local-only reviewer UI. No API key in HTML, no telemetry, no CDN."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import json,secrets,threading,urllib.parse,webbrowser
from .pipeline import analyze,load_jsonl
from .core import Settings
ROOT=Path(__file__).resolve().parents[1]

SCENARIOS={'normal':'normal.jsonl','automation':'automation.jsonl',
           'scan':'scripted_scan.jsonl','adaptive':'adaptive_illustration.jsonl'}

def serve(detector,port=8765,open_browser=True):
    token=secrets.token_urlsafe(32); gate=threading.Lock(); salt=secrets.token_bytes(32)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,code,body,ctype='application/json; charset=utf-8'):
            if isinstance(body,(dict,list)):body=json.dumps(body,ensure_ascii=True).encode()
            elif isinstance(body,str):body=body.encode()
            self.send_response(code);self.send_header('Content-Type',ctype)
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def valid_host(self):
            return self.headers.get('Host') in {f'127.0.0.1:{port}',f'localhost:{port}'}
        def do_GET(self):
            if not self.valid_host():return self.send(403,{'error':'Unexpected Host'})
            path=urllib.parse.urlsplit(self.path).path
            if path=='/':
                s=(ROOT/'web/index.html').read_text().replace('__TOKEN__',token)
                return self.send(200,s,'text/html; charset=utf-8')
            if path=='/api/info':return self.send(200,{'engine':'jev' if detector.__class__.__name__=='JevDetector' else 'rules','version':'0.1.0'})
            types={'/app.js':'application/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}
            if path in types:return self.send(200,(ROOT/'web'/path[1:]).read_bytes(),types[path])
            return self.send(404,{'error':'Not found'})
        def do_POST(self):
            if not self.valid_host() or self.headers.get('X-Demo-Token')!=token:
                return self.send(403,{'error':'Local UI token required'})
            if self.path!='/api/analyze':return self.send(404,{'error':'Not found'})
            try:length=int(self.headers.get('Content-Length','0'))
            except ValueError:return self.send(400,{'error':'Invalid length'})
            if not 0<length<=2000000:return self.send(413,{'error':'Request limit is 2 MB'})
            if not gate.acquire(blocking=False):return self.send(409,{'error':'An analysis is already running'})
            try:
                d=json.loads(self.rfile.read(length));live=detector.__class__.__name__=='JevDetector'
                if live and d.get('consent') is not True:
                    return self.send(400,{'error':'Explicit external-API consent required'})
                if 'rows' in d:
                    rows=d['rows']
                    if not isinstance(rows,list):raise ValueError('rows must be an array')
                else:
                    name=SCENARIOS.get(d.get('scenario','normal'))
                    if not name:raise ValueError('Unknown example')
                    rows=load_jsonl(ROOT/'examples'/name)
                s=Settings(window=int(d.get('window',20)),stride=int(d.get('stride',5)),
                           horizon=int(d.get('horizon',1800)),short_horizon=int(d.get('short_horizon',300)))
                # Cost guard before any live call. Upper bound since first/timeout windows can add calls.
                if live and len(rows)>500:raise ValueError('Live UI limit: 500 events; use CLI for larger studies')
                result=analyze(rows,s,detector,salt=salt,max_calls=500 if live else 10000)
                self.send(200,result)
            except (ValueError,TypeError,KeyError,RuntimeError) as exc:
                self.send(400,{'error':str(exc)})
            except Exception:
                self.send(500,{'error':'Internal error; no verdict returned. See tests and input format.'})
            finally:gate.release()
    srv=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f'Open http://127.0.0.1:{port}/  (Ctrl+C to stop)',flush=True)
    if open_browser:threading.Timer(.5,lambda:webbrowser.open(f'http://127.0.0.1:{port}/')).start()
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
