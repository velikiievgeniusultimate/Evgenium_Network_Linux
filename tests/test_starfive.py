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
    def test_userspace_runtime_installs_only_pinned_safe_members(self):
        import hashlib, io, tarfile
        archive=ROOT/'dist'/('starfive-userspace-x86_64-'+exp.USERSPACE_VERSION+'.tar.gz')
        blob=archive.read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(),exp.USERSPACE_SHA256)
        with tempfile.TemporaryDirectory() as tmp, patch.object(exp,'USERSPACE',Path(tmp)/'runtime'):
            exp.install_userspace_archive(blob)
            self.assertTrue(exp.userspace_ready())
            self.assertEqual((exp.USERSPACE/'charon').stat().st_mode&0o777,0o755)
            fake=io.BytesIO()
            with tarfile.open(fileobj=fake,mode='w:gz') as f:
                info=tarfile.TarInfo('../escape');info.size=1;f.addfile(info,io.BytesIO(b'x'))
            with self.assertRaises(RuntimeError):exp.install_userspace_archive(fake.getvalue())
            self.assertFalse((Path(tmp)/'escape').exists())

    def test_userspace_guard_and_backend_change_are_fail_closed(self):
        with patch.object(exp,'backend',return_value='userspace'):
            rules=exp.render_guard()
            self.assertIn('meta nfproto ipv4 oifname "ipsec0" accept',rules)
            self.assertNotIn('ipsec out reqid',rules)
            self.assertIn('policy drop',rules)
        with patch.object(exp,'active_guard',return_value=True),patch.object(exp,'patch_state') as save:
            with self.assertRaises(RuntimeError):exp.select_backend('kernel')
            save.assert_not_called()

    def test_kernel_failure_is_not_misclassified_as_authentication(self):
        self.assertEqual(exp.failure_code(RuntimeError('authentication successful\nunable to install inbound and outbound IPsec SA (SAD) in kernel')),'kernel_ipsec_unavailable')
        self.assertEqual(exp.failure_code(RuntimeError('authentication successful\nhealth failed')),'other')
        self.assertEqual(exp.failure_code(RuntimeError('authentication failed')),'authentication')

    def test_connection_report_strips_raw_logs_and_rejects_unbounded_fields(self):
        body={'schema':1,'event':'connection_diagnostic','manager':'0.2.22',
              'report_id':'a'*32,'stage':'handshake','error':'timeout','elapsed_ms':55000,
              'guard':True,'ipsec':False,'platform':'steamos','raw_log':'SECRET',
              'ike_sent':5,'ike_received':0,'retransmits':4,'previous_delivery_error':'tcp_timeout'}
        report=collector.clean_report(body)
        self.assertNotIn('SECRET',json.dumps(report))
        self.assertEqual(report['previous_delivery_error'],'tcp_timeout')
        for key,value in [('stage','arbitrary'),('ike_sent',-1),('platform','hostname'),('previous_delivery_error','SECRET')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                collector.clean_report({**body,key:value})

    def test_direct_route_cleanup_and_failure_status_without_raw_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);calls=[]
            def command(args,**kw):
                calls.append(args);return subprocess.CompletedProcess(args,0,'','')
            with patch.object(exp,'ROOT',root),patch.object(exp,'STATE',root/'state.json'), \
                 patch.object(exp,'cmd',side_effect=command), \
                 patch.object(exp.ssl,'create_default_context',side_effect=OSError('SECRET')):
                exp.save({'telemetry':True})
                with self.assertRaises(OSError): exp.direct_endpoint({})
                self.assertEqual(exp.stored()['delivery_error'],'credentials_network')
                self.assertNotIn('SECRET',json.dumps(exp.stored()))
                self.assertEqual(calls[-1][:3],['ip','rule','del'])

    def test_queue_is_bounded_private_and_diagnostics_off_does_not_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(exp,'ROOT',root),patch.object(exp,'STATE',root/'state.json'), \
                 patch.object(exp,'active_guard',return_value=True),patch.object(exp,'connected',return_value=False), \
                 patch.object(exp,'kick_delivery'),patch.object(exp,'cmd',return_value=subprocess.CompletedProcess([],0,'','')):
                exp.save({'telemetry':False});exp.queue_connection('manual','none')
                self.assertFalse((root/'outbox').exists())
                exp.save({'telemetry':True})
                for _ in range(12): exp.queue_connection('handshake','timeout')
                files=list((root/'outbox').glob('*.json'))
                self.assertEqual(len(files),10)
                self.assertEqual(files[0].stat().st_mode & 0o777,0o600)
                for path in files: collector.clean_report(json.loads(path.read_text()))

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
                exp.set_dns(); self.assertIn('77.88.8.8',original.read_text())
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

class GlobalTestTests(unittest.TestCase):
    def test_resumed_chunks_have_expected_content_at_unaligned_offset(self):
        size=170000; cut=67001
        all_data=b''.join(collector.blob_chunks(size))
        resumed=b''.join(collector.blob_chunks(size-cut,cut))
        self.assertEqual(resumed,all_data[cut:])
        self.assertEqual(exp.expected_hash(size-cut,cut),collector.blob_hash(size-cut,cut))
        self.assertEqual(len(all_data),size)

    def test_global_report_drops_unknown_fields(self):
        body={'schema':1,'event':'global_test','manager':'0.2.21','run':'a'*24,
              'outcome':'completed','records':[{'kind':'download','ok':True,'bytes':123,'integrity':True,'secret':'DO_NOT_STORE'}],
              'ip':'DO_NOT_STORE'}
        result=collector.clean_report(body)
        self.assertNotIn('DO_NOT_STORE',json.dumps(result))
        self.assertEqual(result['records'][0]['bytes'],123)

    def test_global_report_rejects_foreign_domains_and_unbounded_metrics(self):
        body={'schema':1,'event':'global_test','manager':'0.2.21','run':'a'*24,'outcome':'completed',
              'records':[{'kind':'ru_probe','ok':True,'domain':'example.com'}]}
        with self.assertRaises(ValueError): collector.clean_report(body)
        body['records']=[{'kind':'download','bytes':float('inf')}]
        with self.assertRaises(ValueError): collector.clean_report(body)
        body['records']=[{'kind':'health'}]*257
        with self.assertRaises(ValueError): collector.clean_report(body)

    def test_pending_report_kept_until_success_and_not_sent_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'pending.json';path.write_text('{}')
            with patch.object(exp,'PENDING_TEST',path),patch.object(exp,'stored',return_value={'telemetry':True}), \
                 patch.object(exp,'connected',return_value=True),patch.object(exp,'deliver_report',side_effect=OSError('offline')):
                with self.assertRaises(OSError): exp.flush_test_report()
                self.assertTrue(path.exists())
            with patch.object(exp,'PENDING_TEST',path),patch.object(exp,'stored',return_value={'telemetry':False}), \
                 patch.object(exp,'deliver_report') as send:
                self.assertFalse(exp.flush_test_report());send.assert_not_called()
            with patch.object(exp,'PENDING_TEST',path),patch.object(exp,'stored',return_value={'telemetry':True}), \
                 patch.object(exp,'connected',return_value=True),patch.object(exp,'deliver_report',return_value=True),patch.object(exp,'test_state'):
                self.assertTrue(exp.flush_test_report());self.assertFalse(path.exists())

    def test_full_worker_retains_guard_and_emits_only_typed_ru_report(self):
        import contextlib,io
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root=Path(tmp)
            for name,value in [('ROOT',root),('STATE',root/'state.json'),('TEST_STATE',root/'test.json'),('PENDING_TEST',root/'pending.json')]:
                stack.enter_context(patch.object(exp,name,value))
            exp.save({'telemetry':True});exp.test_state(phase='running',run='a'*24)
            calls=[]
            def command(args,**kwargs):
                calls.append([str(x) for x in args]);return subprocess.CompletedProcess(args,0,'','')
            stack.enter_context(patch.object(exp,'cmd',side_effect=command))
            stack.enter_context(patch.object(exp,'swan',return_value=subprocess.CompletedProcess([],0,'','')))
            stack.enter_context(patch.object(exp,'connected',return_value=True))
            stack.enter_context(patch.object(exp,'active_guard',return_value=True))
            stack.enter_context(patch.object(exp,'set_dns'))
            stack.enter_context(patch.object(exp.time,'sleep'))
            stack.enter_context(patch.object(exp,'probe_domain',side_effect=lambda d:{'domain':d,'ok':True,'http_status':200}))
            stack.enter_context(patch.object(exp,'ping_test',return_value={'kind':'ping','ok':True}))
            stack.enter_context(patch.object(exp,'transport_counters',return_value={'kind':'counters','ok':True}))
            stack.enter_context(patch.object(exp,'transfer_download',side_effect=lambda *a,**k:{'kind':'download','ok':True,'integrity':True}))
            stack.enter_context(patch.object(exp,'transfer_upload',side_effect=lambda *a,**k:{'kind':'upload','ok':True,'integrity':True}))
            stack.enter_context(patch.object(exp.socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('77.88.55.242',443))]))
            stack.enter_context(patch.object(exp.socket,'create_connection',side_effect=OSError('blocked')))
            data=json.dumps({'probes':[{'domain':d,'ok':True,'latency_ms':1,'http_status':200} for d in exp.RU_DOMAINS],'metrics':{'load1':1}}).encode()
            stack.enter_context(patch.object(exp,'test_request',side_effect=lambda *a,**k:io.BytesIO(data)))
            sent=[]
            def endpoint(path,payload=None):
                if payload is not None: sent.append(payload)
                return {'service':'evgenium-starfive','accepted':True}
            stack.enter_context(patch.object(exp,'endpoint',side_effect=endpoint))
            stack.enter_context(patch.object(exp,'direct_endpoint',side_effect=lambda body: endpoint('/report',body)))
            exp.run_global_test()
            self.assertEqual(exp.test_status()['failed'],0)
            self.assertTrue(exp.test_status()['sent'])
            report=collector.clean_report(sent[0])
            self.assertEqual(report['outcome'],'completed')
            self.assertEqual(sum(x['kind']=='reconnect' for x in report['records']),6)
            self.assertIn(['systemctl','stop',exp.UNIT],calls)
            self.assertFalse(any(c[:2]==['nft','delete'] or exp.GUARD in c for c in calls))

    def test_background_test_refuses_inactive_vpn_without_mutation(self):
        with patch.object(exp,'cmd',return_value=subprocess.CompletedProcess([],3,'','')) as command, \
             patch.object(exp,'stored',return_value={'telemetry':True}),patch.object(exp,'connected',return_value=False):
            with self.assertRaises(RuntimeError): exp.start_global_test()
            self.assertEqual(command.call_count,1)

if __name__=='__main__': unittest.main()
