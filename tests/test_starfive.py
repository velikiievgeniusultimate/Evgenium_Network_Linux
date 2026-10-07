import base64
import ast
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

exp = load('experiment', ROOT / 'src/starfive_experimental.py')
collector = load('collector', ROOT / 'server/diagnostic_collector.py')

class ExperimentalTests(unittest.TestCase):
    def test_only_domains_accepted(self):
        self.assertEqual(exp.domain_only('Example.COM.'), 'example.com')
        for value in ('https://site.example/token', 'site.example?password=x',
                      '127.0.0.1', '::1', 'localhost', 'bad..example', '-bad.example',
                      'site.example\r\nCookie: secret', 'a'*64+'.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                exp.domain_only(value)

    def test_private_dns_answers_are_never_contacted(self):
        answer = [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443)),
                  (socket.AF_INET,socket.SOCK_STREAM,6,'',('192.168.0.1',443))]
        with patch.object(exp.socket,'getaddrinfo',return_value=answer), patch.object(exp.socket,'create_connection') as connect:
            self.assertFalse(exp.probe_domain('site.example')['ok'])
            connect.assert_not_called()

    def test_fail_closed_on_handshake_failure(self):
        calls=[]
        def command(args, **kwargs):
            calls.append([str(x) for x in args])
            return subprocess.CompletedProcess(args,0,'','')
        def swan(*args, **kwargs):
            if '--initiate' in args:
                raise RuntimeError('handshake failed')
            return subprocess.CompletedProcess(args,0,'','')
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp); (r/'profile.json').write_text('{}')
            api=SimpleNamespace(service_active=lambda:False)
            with patch.object(exp,'ROOT',r), patch.object(exp,'RUNTIME',r/'run'), \
                 patch.object(exp,'active_guard',return_value=False), \
                 patch.object(exp.shutil,'which',return_value='/usr/bin/tool'), \
                 patch.object(exp,'validate_profile',return_value={'identity':'device-'+'a'*24}), \
                 patch.object(exp,'service_files'), patch.object(exp,'cmd',side_effect=command), \
                 patch.object(exp,'swan',side_effect=swan), patch.object(exp,'save'), \
                 patch.object(exp,'restore_dns'):
                with self.assertRaisesRegex(RuntimeError,'Kill switch'):
                    exp.on(api,{})
            self.assertIn(['systemctl','enable','--now',exp.GUARD],calls)
            self.assertNotIn(['systemctl','disable','--now',exp.GUARD],calls)
            self.assertFalse(any(c[:3]==['nft','delete','table'] for c in calls))
            self.assertIn(['systemctl','stop',exp.UNIT],calls)

    def test_disabled_diagnostics_never_probe_or_send(self):
        with patch.object(exp,'stored',return_value={'telemetry':False}), \
             patch.object(exp,'probe_domain') as probe, patch.object(exp,'endpoint') as send:
            with self.assertRaises(RuntimeError): exp.report('example.com')
            probe.assert_not_called(); send.assert_not_called()

    def test_other_vpn_is_not_stopped(self):
        with patch.object(exp,'cmd') as cmd:
            with self.assertRaises(RuntimeError):
                exp.on(SimpleNamespace(service_active=lambda:True),{})
            cmd.assert_not_called()

    def test_guard_requires_ipsec_and_blocks_ipv6(self):
        guard=exp.render_guard()
        self.assertIn('policy drop',guard)
        self.assertIn('meta nfproto ipv4 ipsec out reqid 77 accept',guard)
        self.assertIn('meta nfproto ipv4 udp sport 68 udp dport 67',guard)
        self.assertNotIn('flush ruleset',guard)
        self.assertNotIn('ct state established',guard)

    def test_regular_file_dns_is_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp); original=r/'resolv.conf'; original.write_text('nameserver 192.168.0.1\n')
            realpath=Path
            def path(value):
                return original if str(value)=='/etc/resolv.conf' else realpath(value)
            with patch.object(exp,'ROOT',r/'state'), patch.object(exp.pathlib,'Path',side_effect=path), patch.object(exp.shutil,'which',return_value=None):
                exp.set_dns(); self.assertIn('1.1.1.1',original.read_text())
                exp.restore_dns(); self.assertEqual(original.read_text(),'nameserver 192.168.0.1\n')

    def test_embedded_backend_is_identical(self):
        tree=ast.parse((ROOT/'src/vpnctl.py').read_text())
        assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='STARFIVE_EXPERIMENTAL_PY_B64')
        self.assertEqual(base64.b64decode(ast.literal_eval(assignment.value)),(ROOT/'src/starfive_experimental.py').read_bytes())

class CollectorTests(unittest.TestCase):
    def report(self):
        return {'schema':1,'event':'site_report','manager':'0.2.20',
                'probes':[{'domain':'example.com','ok':True,'latency_ms':12,'url':'SECRET'}],
                'ip':'SECRET','password':'SECRET','username':'SECRET'}

    def test_unapproved_fields_never_stored(self):
        body=collector.clean_report(self.report())
        self.assertNotIn('SECRET',json.dumps(body))
        self.assertEqual(set(body),{'schema','event','manager','probes'})

    def test_invalid_domain_and_large_batch_rejected(self):
        for name in ('127.0.0.1','https://example.com/private','bad..example'):
            body=self.report(); body['probes'][0]['domain']=name
            with self.assertRaises(ValueError): collector.clean_report(body)
        body=self.report(); body['probes']*=9
        with self.assertRaises(ValueError): collector.clean_report(body)

    def test_retention_and_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(collector,'LOG',Path(tmp)):
            old=Path(tmp)/'old.jsonl'; old.write_text('old')
            import os,time
            os.utime(old,(time.time()-8*86400,)*2)
            collector.store_report(b'certificate',self.report())
            self.assertFalse(old.exists())
            log=next(Path(tmp).glob('*.jsonl'))
            self.assertEqual(log.stat().st_mode & 0o777,0o600)
            record=json.loads(log.read_text())
            self.assertEqual(len(record['device']),24)
            self.assertNotIn('SECRET',log.read_text())

if __name__=='__main__': unittest.main()
