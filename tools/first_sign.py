#!/usr/bin/env python3
"""Run on the maintainer computer. No network calls; private key stays at home."""
import hashlib
import subprocess
import sys
from pathlib import Path
import rules_tool as tool

ROOT = Path(__file__).resolve().parent.parent
URL = 'https://xunianooo.github.io/allin-rules/current.bin'

def main():
    private = Path.home() / '.allin-rules' / 'private.pem'
    out = ROOT / 'out'
    pubdir = out / 'public'
    bundle = out / 'first-sign'
    public = pubdir / 'public.pem'
    if bundle.exists() or bundle.is_symlink():
        raise ValueError('out/first-sign already exists; inspect and keep the existing signed bundle')
    out.mkdir(exist_ok=True)
    tool.openssl()
    tool.validate((ROOT / 'rules' / 'source.json').read_bytes())
    required = [private, public, pubdir / 'public.der.b64', pubdir / 'fingerprint.sha256']
    present = [p.exists() for p in required]
    if any(present) and not all(present):
        raise ValueError('Partial key setup found; inspect existing files. No key will be replaced')
    if not any(present):
        print('Create an encrypted offline signing key. Keep its passphrase on this computer.')
        tool.init_key(private, pubdir, tool.passphrase(True))
    der = tool.public_der(public)
    fingerprint = hashlib.sha256(der).hexdigest()
    if (pubdir / 'fingerprint.sha256').read_text().strip() != fingerprint:
        raise ValueError('Public fingerprint mismatch; inspect existing files')
    print('Public SPKI SHA256:', fingerprint)
    print('Sign the bootstrap rules with the same private-key passphrase.')
    result = tool.finish(ROOT / 'rules' / 'source.json', private, public, URL, bundle, tool.passphrase())
    tool.verify((bundle / 'current.bin').read_bytes(), bundle / 'public.pem')
    print('Verified rule version:', result['ruleVersion'])
    print('Return ONLY these PUBLIC files:')
    for name in ('current.bin', 'public.pem', 'trust.json'):
        print(str(bundle / name))
    print('Public SPKI SHA256:', fingerprint)
    print('Keep the private key and its passphrase on your computer. Do not send them.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, RecursionError, UnicodeError) as error:
        print('error:', error, file=sys.stderr)
        sys.exit(1)
