#!/usr/bin/env python3
"""Isolated regression: new relay sockets must not select the VPN source IP."""
import json, os, subprocess
ns='evgt-route-test-'+str(os.getpid())
def run(*args):
 return subprocess.check_output(list(args),text=True)
def inside(*args):return run('ip','netns','exec',ns,*args)
def source(port):
 return json.loads(inside('ip','-j','route','get','195.209.211.163','ipproto','tcp','dport',str(port)))[0]['prefsrc']
try:
 run('ip','netns','add',ns)
 inside('ip','link','add','uplink','type','dummy')
 inside('ip','addr','add','172.29.246.2/30','dev','uplink')
 inside('ip','addr','add','10.77.0.33/32','dev','uplink')
 inside('ip','link','set','uplink','up')
 inside('ip','route','add','default','dev','uplink','src','172.29.246.2')
 inside('ip','route','add','table','51822','default','dev','uplink','src','10.77.0.33')
 inside('ip','rule','add','priority','100','lookup','51822')
 assert source(24579)=='10.77.0.33', 'regression not reproduced'
 inside('ip','rule','add','priority','89','to','195.209.211.163/32','ipproto','tcp','dport','24579','lookup','main')
 assert source(24579)=='172.29.246.2', 'relay recursively routed through VPN'
 assert source(443)=='10.77.0.33', 'ordinary traffic bypasses VPN'
 print('PASS: relay reconnect uses uplink; ordinary traffic keeps VPN source')
finally:
 subprocess.run(['ip','netns','del',ns],check=False)
