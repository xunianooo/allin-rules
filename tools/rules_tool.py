#!/usr/bin/env python3
"""Offline All In Q2 rules tooling. Requires Python 3 and OpenSSL CLI."""
import argparse, base64, ctypes, errno, getpass, hashlib, json, os, re, shutil, struct, subprocess, sys, tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
DOMAIN = b'AllIn-Q2\0\1'
WB = {'User-Agent','X-Requested-With','X-Product','X-Agent-Intent','X-Agent-Purpose','X-Conversation-ID','X-Agent-Type','X-Auth-Refresh-Source'}
TUPLES = {('workbuddy','https://copilot.tencent.com','/v2/chat/completions'): WB, ('workbuddy-ai','https://www.workbuddy.ai','/v2/chat/completions'): WB, ('raccoon','https://xiaohuanxiong.com','/api/web/llm/v2/chat/completions'): {'User-Agent','Accept'}}

def fail(message): raise ValueError(message)
def openssl():
    p = shutil.which('openssl')
    if not p and os.name == 'nt':
        for base in (os.environ.get('ProgramFiles', r'C:\Program Files'), os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')):
            for sub in (r'Git\usr\bin\openssl.exe', r'Git\mingw64\bin\openssl.exe'):
                candidate = Path(base) / sub
                if candidate.is_file(): return str(candidate)
    if not p: fail('OpenSSL not found; add it to PATH (Windows Git: Git\\usr\\bin or Git\\mingw64\\bin)')
    return p

def run(args, data=None):
    p = subprocess.run([openssl()] + list(map(str,args)), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode: fail('OpenSSL failed: ' + p.stderr.decode('utf-8','replace').strip())
    return p.stdout

def passphrase(confirm=False):
    p = getpass.getpass('Private key passphrase: ')
    if not p or '\n' in p or '\r' in p or '\0' in p: fail('passphrase must be nonempty and single-line')
    if confirm and p != getpass.getpass('Confirm passphrase: '): fail('passphrases differ')
    return p.encode('utf-8') + b'\n'

def pairs(items):
    result = {}
    for k,v in items:
        if k in result: fail('duplicate JSON key')
        result[k] = v
    return result

def version(v):
    if not isinstance(v,str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}',v): fail('numeric version required')
    return tuple(map(int,v.split('.')))

def string(v,n):
    if not isinstance(v,str) or not v or len(v.encode('utf-16-le','surrogatepass'))//2 > n: fail('invalid string')
    return v

def fields(v,keys):
    if not isinstance(v,dict) or set(v)!=set(keys): fail('invalid fields')

def validate(data):
    if not 0 < len(data) <= 32768: fail('payload size')
    def depth(v,d=0):
        if d>8: fail('JSON depth')
        if isinstance(v,dict):
            for x in v.values(): depth(x,d+1)
        elif isinstance(v,list):
            for x in v: depth(x,d+1)
    obj=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _: fail('invalid number'))
    depth(obj); fields(obj,('schemaVersion','minimumEngineVersion','ruleVersion','rules'))
    if type(obj['schemaVersion']) is not int or obj['schemaVersion']!=1 or type(obj['minimumEngineVersion']) is not int or obj['minimumEngineVersion']!=1: fail('schema version')
    version(obj['ruleVersion'])
    rules=obj['rules']
    if not isinstance(rules,list) or len(rules)>32: fail('rules count')
    ids=set(); tuples=set()
    for r in rules:
        fields(r,('id','provider','protocol','origin','path','headers'))
        ident=string(r['id'],64); provider=string(r['provider'],64); proto=string(r['protocol'],32); origin=string(r['origin'],128); path=string(r['path'],256)
        tup=(provider,origin,path)
        if not re.fullmatch('[a-z0-9._-]+',ident) or ident in ids: fail('rule id')
        if proto!='openai' or tup not in TUPLES or tup in tuples: fail('rule tuple')
        ids.add(ident);tuples.add(tup)
        h=r['headers']
        if not isinstance(h,dict) or set(h)!=TUPLES[tup]: fail('header names')
        for v in h.values():
            string(v,256)
            if not re.fullmatch(r'[\x20-\x7e]+',v) or '${' in v or '{{' in v: fail('header value')
    return obj

def public_der(pub):
    raw=Path(pub).read_bytes()
    if not re.fullmatch(rb'\s*-----BEGIN PUBLIC KEY-----[\sA-Za-z0-9+/=]+-----END PUBLIC KEY-----\s*',raw): fail('SPKI PUBLIC KEY PEM required')
    der=run(['pkey','-pubin','-in',pub,'-pubout','-outform','DER'])
    text=run(['pkey','-pubin','-in',pub,'-text','-noout']).decode('ascii','replace')
    m=re.search(r'Public-Key:\s*\((\d+) bit\)',text)
    if not m or not 2048<=int(m.group(1))<=4096 or 'Modulus:' not in text: fail('RSA public key of 2048–4096 bits required')
    return der

def no_symlinks(path):
    path=Path(path).expanduser().absolute()
    for part in (path,*path.parents):
        if part.is_symlink(): fail('symlink path forbidden')
    return path

def same_path(a,b):
    a=Path(a).expanduser().absolute(); b=Path(b).expanduser().absolute()
    if a.resolve()==b.resolve(): return True
    try: return os.path.samefile(a,b)
    except FileNotFoundError: return False

def atomic(path,data,replace=False,exclusive=False):
    path=no_symlinks(path)
    if not path.parent.is_dir(): fail('output directory missing')
    if path.exists():
        if not path.is_file(): fail('output is not a file')
        if not replace:
            if not exclusive and path.read_bytes()==data: return
            fail('output already exists')
    tmp=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.q2-',delete=False) as f:
            tmp=f.name; f.write(data); f.flush(); os.fsync(f.fileno())
        if replace:
            no_symlinks(path)
            if path.exists() and not path.is_file(): fail('output is not a file')
            os.replace(tmp,path); tmp=None
        else:
            # hard-link publication is exclusive and atomic even under concurrent creation.
            try: os.link(tmp,path)
            except FileExistsError:
                no_symlinks(path)
                if exclusive or not path.is_file() or path.read_bytes()!=data: fail('output already exists')
        if tmp: os.unlink(tmp); tmp=None
    finally:
        if tmp and os.path.exists(tmp): os.unlink(tmp)

def private_path(path,out,existing=False):
    path=no_symlinks(path); out=no_symlinks(out)
    real=path.resolve(); root=ROOT.resolve(); output=out.resolve()
    if real==root or root in real.parents or real==output or output in real.parents: fail('private key must be outside repository and output directory')
    if not existing and real.exists(): fail('private key already exists')
    if existing and not real.is_file(): fail('private key missing')
    return real

def safe_private(path,out): return private_path(path,out)

def init_key(private,out,password):
    private=private_path(private,out); out=no_symlinks(out)
    names=('public.pem','public.der.b64','fingerprint.sha256')
    if any((out/name).exists() or (out/name).is_symlink() for name in names): fail('public output already exists')
    out.mkdir(parents=True,exist_ok=True)
    private.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    created=[]; installed=False
    try:
        # Encrypted temporary key stays in its private directory, never the public stage.
        with tempfile.NamedTemporaryFile(dir=private.parent,prefix='.q2-key-',delete=False) as f:
            staged=Path(f.name)
        try:
            run(['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-aes-256-cbc','-pass','stdin','-out',staged],password)
            pem=run(['pkey','-in',staged,'-passin','stdin','-pubout'],password)
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)/'pub.pem';p.write_bytes(pem);der=public_der(p)
            values=(pem,base64.b64encode(der)+b'\n',(hashlib.sha256(der).hexdigest()+'\n').encode())
            # Reserve private destination exclusively before publishing anything.
            os.link(staged,private); installed=True
            for name,data in zip(names,values):
                dest=out/name
                # init must never accept existing output, even identical bytes.
                if dest.exists() or dest.is_symlink(): fail('public output already exists')
                atomic(dest,data,exclusive=True); created.append(dest)
        finally:
            staged.unlink(missing_ok=True)
    except Exception:
        for dest in created: dest.unlink(missing_ok=True)
        if installed: private.unlink(missing_ok=True)
        raise
    return hashlib.sha256(der).hexdigest()

def publish_dir(stage,out):
    # Require a no-replace directory rename; ordinary POSIX rename can replace an empty directory.
    stage=str(stage); out=str(out)
    if os.name=='nt': os.rename(stage,out); return
    lib=ctypes.CDLL(None,use_errno=True)
    if sys.platform=='darwin':
        fn=getattr(lib,'renamex_np',None); args=(os.fsencode(stage),os.fsencode(out),4)
    else:
        fn=getattr(lib,'renameat2',None); args=(-100,os.fsencode(stage),-100,os.fsencode(out),1)
    if fn is None: fail('atomic no-replace directory rename unavailable')
    if fn(*args)!=0:
        e=ctypes.get_errno(); raise OSError(e,os.strerror(e),out)

def envelope(payload,sig): return b'QRK1'+struct.pack('>I',len(payload))+payload+struct.pack('>H',len(sig))+sig

def unpack(data):
    if len(data)<10 or len(data)>32768+522 or data[:4]!=b'QRK1': fail('envelope format')
    n=struct.unpack('>I',data[4:8])[0]
    if not 1<=n<=32768 or len(data)<10+n: fail('payload size')
    s=struct.unpack('>H',data[8+n:10+n])[0]
    if not 1<=s<=512 or len(data)!=10+n+s: fail('signature size')
    return data[8:8+n],data[10+n:]

def verify(data,pub):
    public_der(pub); payload,sig=unpack(data)
    with tempfile.TemporaryDirectory() as d:
        f=Path(d)/'message';s=Path(d)/'signature'; f.write_bytes(DOMAIN+payload);s.write_bytes(sig)
        run(['dgst','-sha256','-verify',pub,'-signature',s,f])
    return validate(payload)

def sign(source,private,pub,out,password):
    target=no_symlinks(out)
    for input_path in (source,private,pub):
        if same_path(target,input_path): fail('output conflicts with input')
    private_path(private,target.parent,existing=True)
    payload=Path(source).read_bytes(); obj=validate(payload)
    if version(obj['ruleVersion']) <= (1,0,0): fail('rule version must exceed builtin 1.0.0')
    der=public_der(pub)
    derived=run(['pkey','-in',private,'-passin','stdin','-pubout','-outform','DER'],password)
    if der!=derived: fail('private key does not match pinned public key')
    if target.exists():
        old=target.read_bytes(); old_obj=verify(old,pub); old_payload,_=unpack(old)
        if version(obj['ruleVersion'])<version(old_obj['ruleVersion']): fail('rollback')
        if version(obj['ruleVersion'])==version(old_obj['ruleVersion']):
            if payload!=old_payload: fail('version collision')
            return obj
    with tempfile.TemporaryDirectory() as d:
        f=Path(d)/'message';f.write_bytes(DOMAIN+payload)
        sig=run(['dgst','-sha256','-sign',private,'-passin','stdin',f],password)
    result=envelope(payload,sig);verify(result,pub);atomic(target,result,replace=True)
    return obj

def trust(pub,url):
    u=urlsplit(url)
    if not url.isascii() or not re.fullmatch(r'https://[A-Za-z0-9.-]+/[^?#]*',url) or not u.hostname or u.username or u.port is not None or not u.path or any(x in ('.','..','') for x in u.path.split('/')[1:]) or re.search(r'%(?![0-9a-fA-F]{2})',url) or any(ord(c)<=32 or ord(c)>=127 or c in '\\"<>^`{}|' for c in url): fail('strict HTTPS URL required')
    return (json.dumps({'schemaVersion':1,'url':url,'rsaPublicKeySpkiBase64':base64.b64encode(public_der(pub)).decode()},indent=2)+'\n').encode()

def export_trust(pub,url,out):
    if Path(out).suffix.lower()!='.json': fail('trust output must be .json')
    no_symlinks(out)
    if same_path(pub,out): fail('output conflicts with public key')
    atomic(out,trust(pub,url))

def finish(source,private,pub,url,out,password):
    out=no_symlinks(out)
    if out.exists(): fail('finish output directory already exists')
    if not out.parent.is_dir(): fail('finish output parent missing')
    private_path(private,out,existing=True)
    for input_path in (source,pub):
        p=Path(input_path).resolve()
        if p==out.resolve() or out.resolve() in p.parents: fail('output conflicts with input')
    descriptor=trust(pub,url)
    # Stage beside output so final directory rename stays on the same filesystem.
    with tempfile.TemporaryDirectory(dir=out.parent,prefix='.q2-stage-') as temp:
        stage=Path(temp)/'bundle'; stage.mkdir()
        obj=sign(source,private,pub,stage/'current.bin',password)
        atomic(stage/'public.pem',Path(pub).read_bytes())
        atomic(stage/'trust.json',descriptor)
        verify((stage/'current.bin').read_bytes(),stage/'public.pem')
        publish_dir(stage,out)
    return obj

def main():
    ap=argparse.ArgumentParser(description=__doc__); sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('init-key');p.add_argument('--private',default=str(Path.home()/'.allin-rules'/ 'private.pem'));p.add_argument('--out',required=True)
    p=sub.add_parser('validate');p.add_argument('source')
    p=sub.add_parser('verify');p.add_argument('envelope');p.add_argument('--public',required=True)
    p=sub.add_parser('sign');p.add_argument('source');p.add_argument('--private',required=True);p.add_argument('--public',required=True,help='independently pinned public key');p.add_argument('--out',required=True)
    p=sub.add_parser('export-trust');p.add_argument('--public',required=True);p.add_argument('--url',required=True);p.add_argument('--out',required=True)
    p=sub.add_parser('prepare',help='validate and display fingerprint before offline signing');p.add_argument('source');p.add_argument('--public',required=True)
    p=sub.add_parser('finish',help='sign and export public key and trust descriptor');p.add_argument('source');p.add_argument('--private',required=True);p.add_argument('--public',required=True);p.add_argument('--url',required=True);p.add_argument('--out-dir',required=True)
    a=ap.parse_args()
    if a.cmd=='init-key': print('SHA256 SPKI:',init_key(a.private,a.out,passphrase(True)))
    elif a.cmd=='validate': print('Valid:',validate(Path(a.source).read_bytes())['ruleVersion'])
    elif a.cmd=='verify': print('Verified:',verify(Path(a.envelope).read_bytes(),a.public)['ruleVersion'])
    elif a.cmd=='sign': print('Signed:',sign(a.source,a.private,a.public,a.out,passphrase())['ruleVersion'])
    elif a.cmd=='export-trust': export_trust(a.public,a.url,a.out);print('Trust exported')
    elif a.cmd=='prepare': print('Valid:',validate(Path(a.source).read_bytes())['ruleVersion'],'SHA256 SPKI:',hashlib.sha256(public_der(a.public)).hexdigest())
    elif a.cmd=='finish': print('Finished:',finish(a.source,a.private,a.public,a.url,a.out_dir,passphrase())['ruleVersion'])

if __name__=='__main__':
    try: main()
    except (ValueError,OSError,subprocess.SubprocessError,RecursionError,UnicodeError) as e: print('error:',e,file=sys.stderr);sys.exit(1)
