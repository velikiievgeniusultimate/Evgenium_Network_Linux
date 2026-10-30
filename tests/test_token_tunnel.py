import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

issuer = load('issuer', ROOT/'server/token_issuer.py')
tunnel = load('tunnel', ROOT/'src/starfive_tunnel.py')
gui = load('gui', ROOT/'src/evgenium_gui.py')
collector = load('collector', ROOT/'server/diagnostic_collector.py')


class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.pki = cls.root/'pki'; cls.pki.mkdir()
        def run(*args):
            subprocess.run(['openssl', *map(str,args)], check=True, capture_output=True, timeout=30)
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Test CA',
            '-keyout', cls.pki/'ca-key.pem', '-out', cls.pki/'ca.pem')
        (cls.pki/'index.txt').touch(); (cls.pki/'serial').write_text('1000\n')
        (cls.pki/'ca.conf').write_text(f'''[ca]
default_ca=vpn_ca
[vpn_ca]
dir={cls.pki}
database=$dir/index.txt
serial=$dir/serial
new_certs_dir=$dir
certificate=$dir/ca.pem
private_key=$dir/ca-key.pem
default_md=sha256
default_days=30
policy=policy
unique_subject=no
[policy]
commonName=supplied
''')
        cls.csrs=[]
        for index in range(2):
            key=cls.root/f'key{index}.pem';csr=cls.root/f'csr{index}.pem'
            run('req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=untrusted-subject',
                '-keyout',key,'-out',csr)
            cls.csrs.append(csr.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_account_token_is_hashed_and_devices_have_distinct_credentials(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(issuer,'ROOT',Path(tmp)),patch.object(issuer,'PKI',self.pki):
            token=issuer.issue('tester')
            self.assertNotIn(token,(Path(tmp)/'accounts.json').read_text())
            first=issuer.enroll({'token':token,'device':'a'*32,'csr':self.csrs[0]})
            second=issuer.enroll({'token':token,'device':'b'*32,'csr':self.csrs[1]})
            self.assertEqual(first['account'],second['account'])
            self.assertNotEqual(first['identity'],second['identity'])
            self.assertNotEqual(first['certificate'],second['certificate'])
            self.assertNotIn('private_key',first)
            again=issuer.enroll({'token':token,'device':'a'*32,'csr':self.csrs[0]})
            self.assertEqual(again['certificate'],first['certificate'])
            with self.assertRaises(PermissionError):
                issuer.enroll({'token':token,'device':'a'*32,'csr':self.csrs[1]})
            self.assertEqual((Path(tmp)/'accounts.json').stat().st_mode&0o777,0o600)

    def test_disabled_or_invalid_token_never_reaches_certificate_signing(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(issuer,'ROOT',Path(tmp)),patch.object(issuer,'run')as sign:
            token=issuer.issue('disabled')
            data=issuer.accounts(); next(iter(data.values()))['enabled']=False
            issuer.write_json(Path(tmp)/'accounts.json',data)
            for value in (token,'EVN1-'+'a'*43,'not-a-token'):
                with self.assertRaises(PermissionError):issuer.enroll({'token':value,'device':'c'*32,'csr':self.csrs[0]})
            sign.assert_not_called()

    def test_ike_enrollment_after_twelve_revoked_devices_preserves_history(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(issuer,'ROOT',Path(tmp)),patch.object(issuer,'PKI',self.pki):
            token=issuer.issue('replacement');account_id=next(iter(issuer.accounts()))
            data=issuer.accounts();account=data[account_id]
            for number in range(1,13):
                account['devices'][f'{number:032x}']={'identity':'device-'+f'{number:024x}', 'enrolled':number,
                                                       'disabled':True,'revoked':100}
            issuer.ensure_device_names(account);issuer.write_json(Path(tmp)/'accounts.json',data)
            profile=issuer.enroll({'token':token,'device':f'{13:032x}','csr':self.csrs[0]})
            self.assertEqual(profile['device_name'],'Устройство-13')
            self.assertEqual(profile['device_number'],13)
            self.assertEqual(len(issuer.accounts()[account_id]['devices']),13)
            with self.assertRaisesRegex(PermissionError,'device_disabled'):
                issuer.enroll({'token':token,'device':f'{1:032x}','csr':self.csrs[0]})

    def test_ike_enrollment_counts_name_reservations_before_signing(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(issuer,'ROOT',Path(tmp)),patch.object(issuer,'run') as sign:
            token=issuer.issue('reserved')
            for number in range(1,13):issuer.device_info({'token':token,'device':f'{number:032x}'})
            with self.assertRaisesRegex(PermissionError,'device_limit'):
                issuer.enroll({'token':token,'device':f'{13:032x}','csr':self.csrs[0]})
            sign.assert_not_called()


class IsolatedClientTests(unittest.TestCase):
    def test_token_reaches_privileged_action_via_stdin_not_process_arguments(self):
        result=subprocess.CompletedProcess([],0,'ok','')
        with patch.object(gui.subprocess,'run',return_value=result)as run:
            gui.run_vpn(['ui','action','-'],secret_input='SENSITIVE')
        self.assertNotIn('SENSITIVE',str(run.call_args.args))
        self.assertEqual(run.call_args.kwargs['input'],'SENSITIVE')

    def test_cleanup_without_ownership_does_not_change_network(self):
        with tempfile.TemporaryDirectory()as tmp,patch.object(tunnel,'ROOT',Path(tmp)),patch.object(tunnel,'command')as command:
            tunnel.cleanup()
            command.assert_not_called()

    def test_stopped_worker_cannot_report_connected_or_expose_token(self):
        with tempfile.TemporaryDirectory()as tmp,patch.object(tunnel,'ROOT',Path(tmp)),patch.object(tunnel,'STATE',Path(tmp)/'state.json'),patch.object(tunnel,'command',return_value=subprocess.CompletedProcess([],3,'','')):
            tunnel.write(tunnel.ROOT/'token','SECRET')
            tunnel.stage('connected','old',100,active=True,token='SECRET')
            status=tunnel.status()
            self.assertFalse(status['active']);self.assertEqual(status['phase'],'interrupted')
            self.assertNotIn('SECRET',json.dumps(status))

    def test_speed_measurement_never_installs_physical_bypass(self):
        reply=subprocess.CompletedProcess([],0,'200 2097152 2097152 1.0 0.1','')
        with tempfile.TemporaryDirectory() as directory,patch.object(tunnel,'ROOT',Path(directory)),patch.object(tunnel,'STOP',False),patch.object(tunnel,'inside',return_value=reply) as inside,patch.object(tunnel,'command') as host:
            self.assertTrue(tunnel.speed_sample()['available'])
            self.assertEqual(inside.call_count,2)
            self.assertTrue(all(c.args[0][0]=='curl' for c in inside.call_args_list))
            host.assert_not_called()

    def test_lab_filter_preserves_forwarding_disabled_outside_test(self):
        self.assertIn('meta nfproto ipv4 drop', tunnel.host_rules('wlan0', previous_forward=False))
        self.assertNotIn('meta nfproto ipv4 drop', tunnel.host_rules('wlan0', previous_forward=True))
        self.assertNotIn('flush ruleset', tunnel.host_rules('wlan0'))

    def test_public_report_still_requires_client_certificate(self):
        from types import SimpleNamespace
        handler=collector.Handler.__new__(collector.Handler)
        handler.server=SimpleNamespace(enrollment=True,direct_only=True)
        handler.path='/report'
        handler.connection=SimpleNamespace(getpeercert=lambda **_:None)
        with patch.object(handler,'reply')as reply,patch.object(collector,'store_report')as store:
            handler.do_POST()
            reply.assert_called_once_with(403,{'accepted':False})
            store.assert_not_called()
