#!/usr/bin/env python3
"""Create a source-only ZIP from the frozen public manifest. Does not upload."""
from pathlib import Path
import hashlib,zipfile
ROOT=Path(__file__).resolve().parent
manifest=ROOT/'PUBLIC_FILES.txt'
if not manifest.exists():raise SystemExit('PUBLIC_FILES.txt is missing; refusing a broad directory export.')
paths=[x.strip() for x in manifest.read_text().splitlines() if x.strip()]
out=ROOT.parent/'jev-for-web-security-upload.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 for rel in paths:
  p=(ROOT/rel).resolve()
  if not p.is_relative_to(ROOT) or not p.is_file():
   raise SystemExit('Unsafe or missing manifest path: '+rel)
  if p.name.startswith('.env') or 'private_data' in p.parts or 'outputs' in p.parts:
   raise SystemExit('Refusing private/runtime content: '+rel)
  z.write(p,'jev-for-web-security/'+rel)
print('Created:',out)
print('Files:',len(paths),'| SHA-256:',hashlib.sha256(out.read_bytes()).hexdigest())
print('Only manifest-listed files were included. Review changed source and documents for secrets before uploading.')
