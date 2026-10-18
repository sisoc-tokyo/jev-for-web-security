#!/usr/bin/env python3
"""Python 3.10+; no pip install required. Default: offline review dashboard."""
import argparse,getpass,json,os,sys
from pathlib import Path
from jevweb.core import Settings
from jevweb.detectors import RuleDetector,JevDetector
from jevweb.pipeline import analyze,load_jsonl
from jevweb.server import serve

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',nargs='?',choices=['serve','analyze','check'],default='serve')
    p.add_argument('--engine',choices=['rules','jev'],default='rules')
    p.add_argument('--model',default='jev-1.14.0')
    p.add_argument('--ask-key',action='store_true',help='Prompt locally without storing the key')
    p.add_argument('--allow-external-api',action='store_true',help='Required for Jev CLI analysis')
    p.add_argument('--input',type=Path)
    p.add_argument('--output',type=Path,default=Path('outputs/result.json'))
    p.add_argument('--window',type=int,default=20)
    p.add_argument('--stride',type=int,default=5)
    p.add_argument('--horizon',type=int,default=1800)
    p.add_argument('--short-horizon',type=int,default=300)
    p.add_argument('--max-calls',type=int,default=1000)
    p.add_argument('--threshold',type=float,default=.8)
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--no-browser',action='store_true')
    a=p.parse_args()
    if a.command=='check':
        print('Python:',sys.version.split()[0]);print('Mode: no external dependencies')
        print('API key in environment:','present' if os.getenv('TYPESAFE_API_KEY') else 'absent (offline mode works)')
        print('Expected endpoint: https://api.typesafe.ai/v1/systemone');return
    if a.command=='analyze' and a.engine=='jev' and not a.allow_external_api:
        p.error('Jev sends sanitized observations to TypeSafe; add --allow-external-api after data review')
    if a.command=='analyze' and a.input is None:p.error('--input is required for analyze')
    key=getpass.getpass('TypeSafe API key (not saved): ') if a.ask_key and a.engine=='jev' else None
    detector=JevDetector(key,model=a.model,threshold=a.threshold) if a.engine=='jev' else RuleDetector()
    if a.command=='serve':serve(detector,a.port,not a.no_browser)
    else:
        rows=load_jsonl(a.input)
        s=Settings(window=a.window,stride=a.stride,horizon=a.horizon,short_horizon=a.short_horizon)
        salt=os.getenv('JEVWEB_PSEUDONYM_SALT')
        r=analyze(rows,s,detector,salt=salt.encode() if salt else None,max_calls=a.max_calls)
        r['input_sha256']=__import__('hashlib').sha256(a.input.read_bytes()).hexdigest()
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(r,indent=2),encoding='utf-8')
        print(f"Saved {len(r['windows'])} window decisions to {a.output}")
        print('Engine:',a.engine,'| No production accuracy claim.')
if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError) as e:
        print('ERROR:',e,file=sys.stderr);sys.exit(1)
