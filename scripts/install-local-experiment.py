#!/usr/bin/env python3
"""Install the reviewed local manager and GUI without reloading the working Xray."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys

root=Path(__file__).resolve().parents[1]
base=Path('/opt/vpn-manager')
version=(root/'VERSION').read_text().strip()
release=base/'releases'/version
assert os.geteuid()==0
snapshot=Path('/var/lib/vpn-manager/experimental-working-network.json')
config=Path('/run/vpn-manager/config.json')
data={'xray_pid':subprocess.check_output(['systemctl','show','vpn-xray.service','-p','MainPID','--value'],text=True).strip(),
      'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),
      'dns_sha256':hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest(),
      'routes':subprocess.check_output(['ip','-4','route','show','table','main'],text=True),
      'rules':subprocess.check_output(['ip','rule','show'],text=True),
      'guard':subprocess.check_output(['nft','list','table','inet','vpn_guard'],text=True),
      'previous_release':str((base/'current').resolve())}
if not snapshot.exists():
 snapshot.write_text(json.dumps(data));snapshot.chmod(0o600)
release.mkdir(mode=0o755,exist_ok=True)
for name in ['vpnctl.py','vpnadmin.py']:
 target=release/name
 shutil.copyfile(root/'src'/name,target);target.chmod(0o755)
shutil.copyfile(root/'VERSION',release/'VERSION')
subprocess.run([sys.executable,str(release/'vpnctl.py'),'--self-test'],check=True)
link=base/'current-experimental-new';link.unlink(missing_ok=True);link.symlink_to(release);os.replace(link,base/'current')
# This operation writes only GUI files, launchers and icons. No after-update network hook.
subprocess.run([sys.executable,str(release/'vpnctl.py'),'gui','install'],check=True)
assert subprocess.check_output(['systemctl','show','vpn-xray.service','-p','MainPID','--value'],text=True).strip()==data['xray_pid']
assert hashlib.sha256(config.read_bytes()).hexdigest()==data['config_sha256']
assert hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()==data['dns_sha256']
print('Local experimental manager/GUI installed; working Xray PID/config/DNS unchanged.')
