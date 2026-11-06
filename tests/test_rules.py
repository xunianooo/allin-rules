import copy, importlib.util, json, os, subprocess, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rules_tool',ROOT/'tools/rules_tool.py'); t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

class RulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.d=Path(cls.tmp.name);cls.password=b'test password\n'
        cls.private=cls.d/'secret'/'key.pem';cls.pub=cls.d/'published'/'public.pem';cls.outputs=cls.d/'outputs';cls.outputs.mkdir()
        t.init_key(cls.private,cls.pub.parent,cls.password)
        cls.other=cls.d/'other'/'key.pem';cls.otherpub=cls.d/'otherpub'/'public.pem'
        t.init_key(cls.other,cls.otherpub.parent,cls.password)
        cls.source=ROOT/'rules/source.json';cls.original=cls.source.read_bytes()
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def test_roundtrip_tampering_wrongkey(self):
        out=self.outputs/'roundtrip.bin'; t.sign(self.source,self.private,self.pub,out,self.password)
        data=out.read_bytes();self.assertEqual(t.verify(data,self.pub)['ruleVersion'],'1.0.1')
        broken=bytearray(data);broken[20]^=1
        with self.assertRaises(ValueError):t.verify(bytes(broken),self.pub)
        with self.assertRaises(ValueError):t.verify(data,self.otherpub)
        with self.assertRaises(ValueError):t.sign(self.source,self.private,self.otherpub,self.outputs/'wrong.bin',self.password)
    def test_schema(self):
        x=json.loads(self.original);x['rules'][0]['headers']['Authorization']='bad'
        with self.assertRaises(ValueError):t.validate(json.dumps(x).encode())
        with self.assertRaises(ValueError):t.validate(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises((ValueError,UnicodeError)):t.validate(b'\xff')
        x=json.loads(self.original);x['ruleVersion']='01.0.1'
        with self.assertRaises(ValueError):t.validate(json.dumps(x).encode())
        x=json.loads(self.original);x['rules'][0]['headers']['User-Agent']='${secret}'
        with self.assertRaises(ValueError):t.validate(json.dumps(x).encode())
    def test_version_and_atomic_failure(self):
        out=self.outputs/'version.bin';t.sign(self.source,self.private,self.pub,out,self.password);before=out.read_bytes()
        x=json.loads(self.original);x['rules'][0]['headers']['User-Agent']='changed';f=self.d/'different.json';f.write_text(json.dumps(x))
        with self.assertRaises(ValueError):t.sign(f,self.private,self.pub,out,self.password)
        x['ruleVersion']='1.0.0';f.write_text(json.dumps(x))
        with self.assertRaises(ValueError):t.sign(f,self.private,self.pub,out,self.password)
        self.assertEqual(out.read_bytes(),before)
        with self.assertRaises((ValueError,OSError)):t.sign(self.source,self.private,self.pub,self.d/'missing'/'out.bin',self.password)
        with self.assertRaises(ValueError):t.sign(self.source,self.private,self.pub,self.private,self.password)
    def test_key_path_security(self):
        with self.assertRaises(ValueError):t.safe_private(ROOT/'private.pem',self.d/'out')
        with self.assertRaises(ValueError):t.safe_private(self.d/'out'/'private.pem',self.d/'out')
        link=self.d/'alias'
        try: link.symlink_to(ROOT,target_is_directory=True)
        except (OSError,NotImplementedError): self.skipTest('symlinks unavailable')
        with self.assertRaises(ValueError):t.safe_private(link/'private.pem',self.d/'out')
        with self.assertRaises(ValueError):t.safe_private(self.private,self.d/'out')
    def test_init_preserves_existing(self):
        out=self.d/'published'; prior=(out/'public.pem').read_bytes(); new=self.d/'fresh'/'private.pem'
        with self.assertRaises(ValueError):t.init_key(new,out,self.password)
        self.assertFalse(new.exists());self.assertEqual((out/'public.pem').read_bytes(),prior)
        prior_private=self.private.read_bytes()
        with self.assertRaises(ValueError):t.init_key(self.private,self.d/'freshpub',self.password)
        self.assertEqual(self.private.read_bytes(),prior_private)

    def test_init_concurrent_identical_output_is_not_removed(self):
        out=self.d/'race-out'; private=self.d/'race-key'/'private.pem'
        real_atomic=t.atomic
        def raced(path,data,replace=False,exclusive=False):
            if Path(path).name=='public.pem':
                Path(path).write_bytes(data)  # another process wins after precheck
            return real_atomic(path,data,replace,exclusive)
        with mock.patch.object(t,'atomic',side_effect=raced):
            with self.assertRaises(ValueError): t.init_key(private,out,self.password)
        self.assertTrue((out/'public.pem').is_file())
        self.assertFalse(private.exists())

    def test_conflicts_and_wrong_password(self):
        for target in (self.source,self.private,self.pub):
            before=target.read_bytes()
            with self.assertRaises(ValueError):t.sign(self.source,self.private,self.pub,target,self.password)
            self.assertEqual(before,target.read_bytes())
        hard=self.d/'hard';os.link(self.pub,hard)
        with self.assertRaises(ValueError):t.sign(self.source,self.private,self.pub,hard,self.password)
        out=self.outputs/'bad-password.bin'
        with self.assertRaises(ValueError):t.sign(self.source,self.private,self.pub,out,b'wrong\n')
        self.assertFalse(out.exists())
        with self.assertRaises(ValueError):t.public_der(self.private)
        hardkey=self.outputs/'hard-key';os.link(self.private,hardkey)
        with self.assertRaises(ValueError):t.sign(self.source,self.private,self.pub,hardkey,self.password)
        self.assertEqual(self.private.read_bytes(),hardkey.read_bytes())

    def test_export_no_overwrite(self):
        target=self.d/'trust.json';target.write_bytes(b'original')
        with self.assertRaises(ValueError):t.export_trust(self.pub,'https://example.org/current.bin',target)
        self.assertEqual(target.read_bytes(),b'original')
        with self.assertRaises(ValueError):t.export_trust(self.pub,'https://example.org/current.bin',self.pub)
        fresh=self.d/'fresh-trust.json';t.export_trust(self.pub,'https://example.org/current.bin',fresh)
        t.export_trust(self.pub,'https://example.org/current.bin',fresh)

    def test_finish_atomic(self):
        out=self.d/'bundle-failure'
        with mock.patch.object(t,'atomic',side_effect=OSError('injected output failure')):
            with self.assertRaises(OSError):t.finish(self.source,self.private,self.pub,'https://example.org/current.bin',out,self.password)
        self.assertFalse(out.exists())
        real_atomic=t.atomic
        def fail_second(path,data,replace=False,exclusive=False):
            if Path(path).name=='public.pem': raise OSError('injected second output failure')
            return real_atomic(path,data,replace,exclusive)
        with mock.patch.object(t,'atomic',side_effect=fail_second):
            with self.assertRaises(OSError):t.finish(self.source,self.private,self.pub,'https://example.org/current.bin',out,self.password)
        self.assertFalse(out.exists())
        with self.assertRaises(ValueError):t.finish(self.source,self.private,self.pub,'http://example.org/x',out,self.password)
        self.assertFalse(out.exists())
        out=self.d/'bundle-success';t.finish(self.source,self.private,self.pub,'https://example.org/current.bin',out,self.password)
        self.assertEqual(set(p.name for p in out.iterdir()),{'current.bin','public.pem','trust.json'})
        with self.assertRaises(ValueError):t.finish(self.source,self.private,self.pub,'https://example.org/current.bin',out,self.password)
        t.verify((out/'current.bin').read_bytes(),out/'public.pem')

    def test_cli_and_offline(self):
        # Network APIs are unavailable throughout the entire in-process operation.
        with mock.patch('socket.socket',side_effect=AssertionError('network used')):
            out=self.outputs/'offline.bin';t.sign(self.source,self.private,self.pub,out,self.password);t.verify(out.read_bytes(),self.pub)
        cmd=[sys.executable,str(ROOT/'tools/rules_tool.py'),'validate',str(self.source)]
        result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('1.0.1',result.stdout)
        out=self.d/'cli-trust.json'
        cmd=[sys.executable,str(ROOT/'tools/rules_tool.py'),'export-trust','--public',str(self.pub),'--url','https://example.org/current.bin','--out',str(out)]
        result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(out.is_file())

    def test_trust(self):
        obj=json.loads(t.trust(self.pub,'https://example.org/rules/current.bin'))
        self.assertEqual(set(obj),{'schemaVersion','url','rsaPublicKeySpkiBase64'})
        for url in ('http://example.org/x','https://user@example.org/x','https://example.org:443/x','https://example.org/a/../x','https://example.org/x?q=1'):
            with self.assertRaises(ValueError):t.trust(self.pub,url)

if __name__=='__main__':unittest.main()
