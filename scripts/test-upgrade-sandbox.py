#!/usr/bin/env python3
"""Offline filesystem integration: real 0.2.7 updater + independent repair bootstrap.

Uses bubblewrap namespaces and disposable /etc,/opt,/var,/run,/home,/usr/local.
No host services, networking, user data or installed VPN are modified. System
services are stubbed: this tests upgrade files and migration, not a live tunnel.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
VERSION=(ROOT/'VERSION').read_text().strip()

def load(path):
    s=importlib.util.spec_from_file_location('fixture_manager',Path(path).resolve())
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def setup(legacy=True):
    for p in ('/etc/vpn-manager','/etc/systemd/system','/opt/vpn-manager/releases',
              '/opt/vpn-manager/bin','/usr/local/bin','/usr/local/sbin','/var/lib/vpn-manager','/home/fixture/Vpn/VPN configs'):
        Path(p).mkdir(parents=True,exist_ok=True)
    Path('/etc/passwd').write_text('fixture:x:0:0::/home/fixture:/bin/bash\n')
    Path('/etc/group').write_text('fixture:x:0:\n')
    Path('/opt/vpn-manager/bin/xray').write_text('#!/bin/sh\necho Xray 26.7.28\n')
    Path('/opt/vpn-manager/bin/xray').chmod(0o755)
    private=Path('/etc/vpn-manager/starfive-tunnel');private.mkdir(mode=0o700,exist_ok=True)
    binary_name=json.loads((ROOT/'fixture-evgt.json').read_text())['name']
    (private/binary_name).write_bytes((ROOT/'fixture-evgt').read_bytes());(private/binary_name).chmod(0o700)
    if not legacy:return
    data={'engine':'xray','owner_user':'fixture','owner_home':'/home/fixture',
          'config_dir':'/home/fixture/Vpn/VPN configs','direct_sites':'/home/fixture/Vpn/DIRECT sites.txt',
          'direct_networks':'/home/fixture/Vpn/DIRECT networks.txt','xray_uid':0,'xray_gid':0,
          'manager_manifest_url':'https://fixture.test/stable.json','custom_keep':'keep-me'}
    Path('/etc/vpn-manager/settings.json').write_text(json.dumps(data))
    Path(data['direct_sites']).write_text('domain:example.org\n')
    Path(data['direct_networks']).write_text('192.0.2.0/24\n')
    Path('/home/fixture/Vpn/DIRECT apps.txt').write_text('my-app\n')
    Path('/home/fixture/Vpn/SERVER ports.txt').write_text('tcp 25565\n')
    Path(data['config_dir']+'/old.json').write_text('legacy-profile-fixture')
    old=Path('/opt/vpn-manager/releases/0.2.7');old.mkdir()
    with tarfile.open(ROOT/'dist/vpn-manager-0.2.7.tar.gz') as t:t.extractall(old,filter='data')
    Path('/opt/vpn-manager/current').symlink_to(old)
    Path('/usr/local/sbin/vpnctl').symlink_to('/opt/vpn-manager/current/vpnctl.py')
    load(old/'vpnctl.py').sync_system_files()
    gui=Path('/home/fixture/.local/share/evgenium-network');gui.mkdir(parents=True)
    (gui/'evgenium_gui.py').write_text('STALE GUI')
    (gui/'evgenium_gui.qml').write_text('STALE QML')
    return data

def old_update():
    old=load('/opt/vpn-manager/releases/0.2.7/vpnctl.py')
    old.http_get=lambda url,*args: (ROOT/'update/stable.json').read_bytes() if url.endswith('stable.json') else (ROOT/f'dist/vpn-manager-{VERSION}.tar.gz').read_bytes()
    # Everything after exec is the shipped new manager, not this monkeypatch.
    old.main(['update'])

def bootstrap():
    source=Path('/tmp/fresh');source.mkdir(exist_ok=True)
    with tarfile.open(ROOT/f'dist/vpn-manager-{VERSION}.tar.gz') as t:t.extractall(source,filter='data')
    shell=(ROOT/'install.sh').read_text()
    block=shell.split('"${tmp}/release" <<\'PY\'\n',1)[1].split('\nPY\n',1)[0]
    sys.argv=['-', 'fixture','/home/fixture','0','0','https://fixture.test/stable.json',str(source)]
    exec(compile(block,'installer-bootstrap','exec'),{'__name__':'__main__'})

def verify():
    new=load('/usr/local/sbin/vpnctl')
    assert new.MANAGER_VERSION==VERSION
    assert Path('/usr/local/bin/vpn').read_text()==new.WRAPPER_TEXT
    for name,source in [('evgenium_gui.py',new.STANDALONE_GUI_PY_B64),('evgenium_gui.qml',new.STANDALONE_GUI_QML_B64)]:
        assert (Path('/home/fixture/.local/share/evgenium-network')/name).read_bytes()==base64.b64decode(source)
    assert Path('/usr/local/sbin/vpn-manager-admin').resolve()==Path('/opt/vpn-manager/current/vpnadmin.py').resolve()
    assert not new.INSTALL_PENDING.exists()
    assert json.loads(new.INSTALL_COMPLETE.read_text())['version']==VERSION
    policy=json.loads(Path('/etc/vpn-manager/policy.json').read_text())
    assert 'example.org' in policy['networks'] and '192.0.2.0/24' in policy['networks']
    assert 'my-app' in policy['applications'] and 'tcp:25565:in' in policy['ports']
    assert json.loads(Path('/etc/vpn-manager/settings.json').read_text())['custom_keep']=='keep-me'
    subprocess.run(['/usr/local/sbin/vpnctl','version'],check=True)
    assert 'Подключить' in subprocess.check_output(['/usr/local/sbin/vpnctl','--help'],text=True)

def inside():
    setup()
    subprocess.run([sys.executable,__file__,'--old-update'],check=True)
    verify();print('PASS: original 0.2.7 updater -> new CLI/GUI, migrated exceptions')
    # A partial 0.4.x install with a broken CLI and stale GUI. Preserve credentials.
    private=Path('/etc/vpn-manager/starfive-tunnel');private.mkdir(exist_ok=True)
    (private/'token').write_text('EVN1-'+'a'*43)
    (private/'device.key').write_text('private-key-fixture')
    before={p.name:p.read_bytes() for p in private.iterdir() if p.is_file()}
    old_target=Path('/opt/vpn-manager/current').resolve()
    Path('/usr/local/sbin/vpnctl').unlink();Path('/usr/local/sbin/vpnctl').write_text('BROKEN CLI')
    subprocess.run([sys.executable,__file__,'--bootstrap'],check=True)
    assert old_target.exists() and Path('/opt/vpn-manager/current').resolve()!=old_target
    subprocess.run(['/usr/local/sbin/vpnctl','internal-sync'],check=True)
    verify()
    for name,contents in before.items():assert (private/name).read_bytes()==contents
    backups=list(Path('/var/lib/vpn-manager/backups').glob('*.tar.gz'));assert backups
    assert backups[0].stat().st_mode&0o777==0o600
    with tarfile.open(backups[0]) as t:assert t.extractfile('etc/vpn-manager/starfive-tunnel/token').read()==before['token']
    print('PASS: independent reinstall repairs broken CLI, keeps token/key/policy, creates private backup')
    Path('/etc/vpn-manager/settings.json').write_text('{broken')
    subprocess.run([sys.executable,__file__,'--bootstrap'],check=True)
    subprocess.run(['/usr/local/sbin/vpnctl','internal-sync'],check=True)
    assert json.loads(Path('/etc/vpn-manager/settings.json').read_text())['owner_user']=='fixture'
    for name,contents in before.items():assert (private/name).read_bytes()==contents
    assert 'example.org' in json.loads(Path('/etc/vpn-manager/policy.json').read_text())['networks']
    print('PASS: corrupt settings repaired without losing token/key/policy')

def fresh():
    setup(legacy=False)
    subprocess.run([sys.executable,__file__,'--bootstrap'],check=True)
    subprocess.run(['/usr/local/sbin/vpnctl','internal-sync'],check=True)
    new=load('/usr/local/sbin/vpnctl')
    assert json.loads(new.INSTALL_COMPLETE.read_text())['version']==VERSION
    assert Path('/usr/local/bin/vpn').read_text()==new.WRAPPER_TEXT
    assert Path('/home/fixture/.local/share/evgenium-network/evgenium_gui.qml').read_bytes()==base64.b64decode(new.STANDALONE_GUI_QML_B64)
    print('PASS: fresh installation without existing settings or CLI')

if __name__=='__main__':
    if '--old-update' in sys.argv:old_update()
    elif '--bootstrap' in sys.argv:bootstrap()
    elif '--inside' in sys.argv:inside()
    elif '--fresh' in sys.argv:fresh()
    else:
        import shutil
        if not shutil.which('bwrap'):raise SystemExit('bubblewrap required; run unit tests if unavailable')
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)
            # A root user namespace cannot traverse a runner-owned 0700 home.
            # Copy only public fixture files into the invoking user's temp dir.
            snapshot=fake/'source'
            for name in ('VERSION','install.sh','update/stable.json','dist/vpn-manager-0.2.7.tar.gz',
                         f'dist/vpn-manager-{VERSION}.tar.gz','scripts/test-upgrade-sandbox.py'):
                target=snapshot/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(ROOT/name,target)
            # Download and verify the pinned dependency before entering offline namespaces.
            manager=load(ROOT/'src/vpnctl.py')
            manager.starfive_tunnel.ROOT=fake/'transport-cache'
            supplied=os.environ.get('EVG_TEST_TUNNEL')
            if supplied:
                manager.starfive_tunnel.ROOT.mkdir()
                target=manager.starfive_tunnel.ROOT/('evgenium-tunnel-'+manager.starfive_tunnel.EVGT_VERSION)
                shutil.copy2(supplied,target)
            binary=manager.starfive_tunnel.ensure_evgt_binary()
            shutil.copy2(binary,snapshot/'fixture-evgt')
            (snapshot/'fixture-evgt.json').write_text(json.dumps({'name':binary.name}))
            stub=fake/'systemctl';stub.write_text('#!/bin/sh\ncase "$*" in *is-active*) exit 3;; esac\nexit 0\n');stub.chmod(0o755)
            ip=fake/'ip';ip.write_text('#!/bin/sh\nexit 1\n');ip.chmod(0o755)
            args=['bwrap','--die-with-parent','--unshare-all','--uid','0','--gid','0','--ro-bind','/','/',
                  '--tmpfs','/etc','--tmpfs','/var','--tmpfs','/run','--tmpfs','/opt','--tmpfs','/home',
                  '--tmpfs','/tmp','--tmpfs','/usr/local','--proc','/proc','--dev','/dev',
                  '--ro-bind',str(snapshot),'/tmp/src','--ro-bind',str(stub),'/usr/bin/systemctl',
                  '--ro-bind',str(ip),str(Path(shutil.which('ip')).resolve()),'--chdir','/tmp/src',sys.executable,'/tmp/src/scripts/test-upgrade-sandbox.py','--inside']
            subprocess.run(args,check=True,timeout=120)
            subprocess.run(args[:-1]+['--fresh'],check=True,timeout=120)
