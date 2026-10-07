#!/bin/bash
# Test on the gateway itself, never change a desktop client's routes.
set -euo pipefail
umask 077
testroot=/etc/swanctl/evgenium-selftest
mkdir -p "$testroot" /run/evgenium-selftest
rm -f /run/evgenium-selftest/charon.vici
mkdir -p /etc/netns/evgenium-test
printf 'nameserver 1.1.1.1\n' > /etc/netns/evgenium-test/resolv.conf
cleanup() {
 if [ -f "$testroot/pid" ]; then kill "$(cat "$testroot/pid")" 2>/dev/null || true; fi
 ip netns delete evgenium-test 2>/dev/null || true
 ip link delete evt-server 2>/dev/null || true
 rm -f /etc/netns/evgenium-test/resolv.conf
 rmdir /etc/netns/evgenium-test 2>/dev/null || true
}
trap cleanup EXIT
ip netns add evgenium-test
ip link add evt-server type veth peer name evt-client
ip link set evt-client netns evgenium-test
ip addr add 10.78.0.1/30 dev evt-server
ip -6 addr add 2001:db8:77::1/64 dev evt-server
ip link set evt-server up
ip netns exec evgenium-test ip addr add 10.78.0.2/30 dev evt-client
ip netns exec evgenium-test ip -6 addr add 2001:db8:77::2/64 dev evt-client
ip netns exec evgenium-test ip link set lo up
ip netns exec evgenium-test ip link set evt-client up
ip netns exec evgenium-test ip route add default via 10.78.0.1
python3 - "$testroot" "${EVGENIUM_TEST_PROFILE:-/home/Evgenius/StarFive-test/profile.json}" <<'PY'
import importlib.util,json,sys
from pathlib import Path
r=Path(sys.argv[1])
p=json.loads(Path(sys.argv[2]).read_text())
for name,field in [('ca.pem','ca'),('client.pem','certificate'),('client-key.pem','private_key')]:
 (r/name).write_text(p[field])
for name,field in [('x509ca/ca.pem','ca'),('x509/client.pem','certificate'),('private/client-key.pem','private_key')]:
 (r/name).parent.mkdir(exist_ok=True)
 (r/name).write_text(p[field])
spec=importlib.util.spec_from_file_location('exp','/tmp/starfive_experimental.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=r
(r/'guard.nft').write_text(m.render_guard().replace(m.SERVER,'10.78.0.1'))
(r/'connection.conf').write_text(m.render_connection(p).replace('remote_addrs = 109.194.67.159','remote_addrs = 10.78.0.1'))
PY
cat > "$testroot/strongswan.conf" <<'EOF'
charon {
 load_modular = yes
 install_routes = yes
 routing_table = 51822
 routing_table_prio = 100
 plugins {
  include /etc/strongswan.d/charon/*.conf
  vici {
   socket = unix:///run/evgenium-selftest/charon.vici
  }
  resolve {
   load = no
  }
 }
}
charon-systemd {
 journal {
  default = 1
 }
}
EOF
ip netns exec evgenium-test env STRONGSWAN_CONF="$testroot/strongswan.conf" /usr/sbin/charon-systemd > "$testroot/daemon.log" 2>&1 &
echo $! > "$testroot/pid"
for i in $(seq 1 30); do [ -S /run/evgenium-selftest/charon.vici ] && break; sleep 0.2; done
uri=unix:///run/evgenium-selftest/charon.vici
ip netns exec evgenium-test swanctl --load-creds --file "$testroot/connection.conf" --uri "$uri"
ip netns exec evgenium-test swanctl --load-conns --file "$testroot/connection.conf" --uri "$uri"
ip netns exec evgenium-test nft -c -f "$testroot/guard.nft"
ip netns exec evgenium-test nft -f "$testroot/guard.nft"
if ip netns exec evgenium-test ping -6 -n -c 1 -W 2 2001:db8:77::1 >/dev/null 2>&1; then
 echo 'FAIL: IPv6 leaked'; exit 1
fi
echo 'IPV6_BLOCK_PASS'
ip netns exec evgenium-test swanctl --initiate --child starfive-net --uri "$uri"
ip netns exec evgenium-test swanctl --list-sas --raw --uri "$uri"
ip netns exec evgenium-test python3 - "$testroot" <<'PY'
import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('exp','/tmp/starfive_experimental.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=Path(sys.argv[1]);m.URI='unix:///run/evgenium-selftest/charon.vici';m.RUNTIME=Path('/run/evgenium-selftest')
assert m.connected(), 'SA status must be connected'
print('CONNECTED',True, flush=True)
print('ROUTE',m.cmd(['ip','route','get','1.1.1.1']).stdout, flush=True)
print('PING',m.cmd(['ping','-n','-c','2','-W','2','1.1.1.1'],check=False).stdout, flush=True)
print('DNS',m.cmd(['getent','ahostsv4','example.com'],check=False).stdout, flush=True)
print('HEALTH',m.endpoint('/health'))
import ssl,urllib.request,urllib.error
ctx=ssl.create_default_context(cafile=str(m.ROOT/'ca.pem'))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
try:
 opener.open(m.HEALTH+'/health',timeout=5)
except (OSError,urllib.error.URLError):
 print('MTLS_NO_CERT_DENIED')
else:
 raise AssertionError('collector accepted a request without client certificate')
probe=m.probe_domain('example.com')
print('HTTPS',probe)
# Independent providers below establish transport readiness.
cf=m.probe_domain('www.cloudflare.com'); google=m.probe_domain('www.google.com')
print('CFHTTPS',cf); print('HTTPS_GOOGLE',google)
assert sum(x['ok'] for x in [probe,cf,google]) >= 2, 'HTTPS quorum through guarded tunnel failed'
print('REPORT',m.endpoint('/report',{'schema':1,'event':'sample','manager':'0.2.20','probes':[{'domain':'example.com','ok':True,'latency_ms':1}]}))
PY

# A daemon failure must leave the guard in place and prevent direct egress.
kill "$(cat "$testroot/pid")"
sleep 1
ip netns exec evgenium-test nft list table inet evgenium_ikev2_guard >/dev/null
if ip netns exec evgenium-test ping -n -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
 echo 'FAIL: direct traffic leaked after daemon stop'; exit 1
fi
echo 'KILL_SWITCH_PASS: traffic blocked after daemon stop'
