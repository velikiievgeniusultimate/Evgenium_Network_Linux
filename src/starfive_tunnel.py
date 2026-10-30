"""Token IKEv2 client: isolated transport and guarded full-device Estonia egress."""
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import platform
import urllib.request
import ssl
import subprocess
import time
import sys

ROOT = Path('/etc/vpn-manager/starfive-tunnel')
RUNTIME = Path('/run/evgenium-starfive-tunnel')
STATE = Path('/var/lib/vpn-manager/starfive-tunnel.json')
UNIT = 'evgenium-starfive-tunnel.service'
NS = 'evn-starfive'
HOST = 'evn-sf-host'
PEER = 'evn-sf-peer'
NETWORK = '172.29.246.0/30'
CLIENT = '172.29.246.2'
GATEWAY = '172.29.246.1'
TABLE = 51824
PRIORITY = 75
NFT = 'evgenium_starfive_lab_host'
SERVER = '195.209.211.163'
IKE_PORT = 24550
ENDPOINTS = (SERVER, '38.180.164.67')
CANDIDATES = (
 {'id':'ru-udp','address':SERVER,'identity':SERVER,'port':24550,'tls':False,'label':'HSVDS → Эстония'},
 {'id':'ee-udp','address':'38.180.164.67','identity':'38.180.164.67','port':443,'tls':False,'label':'Эстония напрямую'},
 {'id':'ee-tls','address':'38.180.164.67','identity':'38.180.164.67','port':443,'tls':True,'label':'Эстония через TLS'},
 {'id':'ee-evgt','address':'38.180.164.67','identity':'38.180.164.67','port':443,'tls':False,'evgt':True,'label':'Эстония через EvgeniumTunnel'},
 {'id':'ee-evgt-ru','address':'38.180.164.67','identity':'38.180.164.67','port':443,'tls':False,'evgt':True,'transport_address':SERVER,'transport_port':24579,'label':'EvgeniumTunnel · HSVDS → Эстония'},
)
ACTIVE = CANDIDATES[0]
rank_api = None
support_api = None
tls_api = None
TLS_PROCESS = None
# Kept only for removing routes installed by pre-migration versions.
LEGACY_ENDPOINTS = ('109.194.67.159', '192.168.0.163')
HEALTH = '10.77.0.1'
REQID = 177
TOKEN_PATTERN = r'EVN1-[A-Za-z0-9_-]{43}'
STOP = False
DNS_PROCESS = None
policy = None
PINNED_CA = '-----BEGIN CERTIFICATE-----\nMIIEODCCAqCgAwIBAgIUbkJ+8SaqAgwY1RDAjZRTjcqQ9eMwDQYJKoZIhvcNAQEL\nBQAwIjEgMB4GA1UEAwwXRXZnZW5pdW0gcHJpdmF0ZSBWUE4gQ0EwHhcNMjYxMDA3\nMTkxMzQxWhcNMzYxMDA0MTkxMzQxWjAiMSAwHgYDVQQDDBdFdmdlbml1bSBwcml2\nYXRlIFZQTiBDQTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAOZ+nviE\n2OrF7Pdtkk/XIaFVIvJlvC11VZf9rljCBIvBykbsrArGryQHGnuuXLNaaS8NtLxY\nNeSBDK6MdgYJAejsP4wITub3nMjSG2umIIVU6mE+GDozGPlNMNJ+bhkKaVhaPjFE\nyYLYrdPe5VA4w+5p0NZOD6CBHD3tEXWBNRIeVSWbtMITsOES1Pe/aAL7v3oNIVkV\n8nDw9j7+wG2y5dhbp7KUJHbrDB024r7cYrQ3axYF6gykjmztpKXsbkxQv27BvhSB\ne0EktJ/jCS6R9IImYgIQrCraWZmVScnGF/Aq4TNw1H4OzFCkR+7JUlYnSYUvMRi1\nLzKekUC+2/0WFmhnCoDtdjcoYbxpLpKDelGiS3RsNCvxnslMaPz5hCcF64Y7RijX\nj6DuCYpFYWlr13B20qAnRoUas+AjX7PXCkR4xOhH+kW8/HmFHiHkohWE0wllISBX\nVBo7KBOZd8SVewybd2rB4soXouTtjXs/jTge+HWxQDGPP1umfz8cFLR/uQIDAQAB\no2YwZDAdBgNVHQ4EFgQUoQfTif77xWt06haXh3ha890qkT8wHwYDVR0jBBgwFoAU\noQfTif77xWt06haXh3ha890qkT8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B\nAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggGBAI7GKnmfJjuL1QvyRtlw+Hr6AY/Z\nOxdDvECefoFL7Q41VZa+L7DI87kMLYHygRHush66oUv878TWMtasnbt/8wYg6jrw\nAygpg/F3VD24yTrnJ7OCdyGib6LGuusuTP4rUGsccWcznQXYFkzRVz1VeYMZUN+P\ntAViNl4ERS1fh+cGzT4OqXQkJDkReqH/HCTE8kUQUUgXaSXphKjGa8pR2HVeFukX\n+0pp1iR+6di4aCKapkaTiVR3r62tRBUwbxoFYRyxNXynTK9EhnM25WEpn/qu0lsD\noXrFVmj0AQfAUHRN/2rPL//w6RPEpHgUcrt7zuSgoXJZh0DT30VEIK9NNbuKSFd9\nIiWvrxbVQS6mQgtEZN4Lc2Hm1pvY+WrI+H03u8042+cpLIsCnxPm9Wvi7dMXxqob\no2/aL2xDG5G/8WVR/W5EAfvKdxdrk3H602occov7+Jg1voxi00IbdMExoMxd5aeh\nfXRiJhTEFouIpmESCF4vVMlWFr3mqlQ3GKSPVA==\n-----END CERTIFICATE-----\n'


FULL_HOST = 'evn-full-host'
FULL_PEER = 'evn-full-peer'
FULL_NET = '172.29.247.0/30'
FULL_TABLE = '51828'
ADMIN_TABLE = '51829'
FULL_GUARD = 'evn_starfive_full'
def full_state():
    return ROOT/'full-network.json'


def charon_binary():
    candidates = ('/usr/sbin/charon-systemd', '/usr/bin/charon-systemd',
                  '/usr/lib/ipsec/charon-systemd', '/usr/libexec/ipsec/charon-systemd',
                  '/usr/lib/strongswan/charon-systemd', '/usr/libexec/strongswan/charon-systemd')
    return next((p for p in candidates if Path(p).is_file()), None)


EVGT_VERSION = '0.3.0'
EVGT_ASSETS = {
 'x86_64': ('amd64','fdcc94d65ea6c3da768f66660021783daa45c3656cc946bafd5111a86bb285a6'),
 'aarch64': ('arm64','4333c1a74badab6387e8a5bbf2f1e2f4f409da2037e94b32e8466b700688c02d'),
 'riscv64': ('riscv64','fc0c14c0fb4bd0aec22d771bad2131f7a5df059d6f7fb537c465f1f2ae25a21f'),
}

def ensure_evgt_binary():
    asset=EVGT_ASSETS.get(platform.machine())
    if asset is None:raise RuntimeError('evgt_arch_unsupported')
    arch,digest=asset
    path=ROOT/('evgenium-tunnel-'+EVGT_VERSION)
    if path.is_symlink():raise RuntimeError('evgt_binary_symlink')
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest:
        path.chmod(0o700);return path
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    url='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/evgenium-tunnel-v'+EVGT_VERSION+'/evgenium-tunnel-linux-'+arch
    with urllib.request.urlopen(url,timeout=30) as response:blob=response.read(16*1024*1024+1)
    if len(blob)>16*1024*1024 or hashlib.sha256(blob).hexdigest()!=digest:
        raise RuntimeError('evgt_binary_checksum_failed')
    tmp=path.with_name(path.name+'.new')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o700)
    try:
        with os.fdopen(fd,'wb') as output:output.write(blob);output.flush();os.fsync(output.fileno())
        os.chmod(tmp,0o700);os.replace(tmp,path)
    finally:tmp.unlink(missing_ok=True)
    return path


def ensure_dependencies():
    if charon_binary() and all(shutil.which(p) for p in ('swanctl','ip','nft','curl','openssl','conntrack')):
        ensure_evgt_binary()
        return
    stage('dependencies', 'Устанавливаю необходимые системные компоненты VPN.', 3, active=False)
    if shutil.which('pacman'):
        args = ['pacman','-S','--needed','--noconfirm','strongswan','iproute2','nftables','curl','openssl','ca-certificates','conntrack-tools']
    elif shutil.which('dnf'):
        args = ['dnf','install','-y','--setopt=install_weak_deps=False','strongswan','iproute','nftables','curl','openssl','ca-certificates','conntrack-tools']
    else:
        raise RuntimeError('Автоматическая установка клиента поддерживает Arch и Fedora.')
    command(args, timeout=300)
    if not charon_binary() or not all(shutil.which(p) for p in ('swanctl','conntrack')):
        raise RuntimeError('Пакет strongSwan не предоставил необходимые программы.')
    ensure_evgt_binary()


def clear_dns_mappings(previous_vpn=False):
    """Forget only this manager's obsolete DNS NAT, never flush all connections.

    Removing an nft NAT chain does not remove existing conntrack translations.
    A running resolver can reuse its UDP socket indefinitely after a VPN switch.
    """
    filters = (['--reply-port-src','18553'] if previous_vpn else
               ['--reply-port-src','53','--dst-nat','1.1.1.1'])
    for protocol in ('udp','tcp'):
        result = command(['conntrack','-D','-f','ipv4','-p',protocol,
                          '--dport','53',*filters], check=False,
                         env={**os.environ,'LC_ALL':'C'})
        empty = result.returncode == 1 and '0 flow entries have been deleted' in result.stderr
        if result.returncode != 0 and not empty:
            raise RuntimeError('dns_transition_cleanup_failed')


def full_guard_active():
    return command(['nft','list','table','inet',FULL_GUARD],check=False).returncode == 0


def full_firewall():
    if policy is not None:
        settings=policy.api.load_settings()
        return policy.firewall(policy.load(),policy.local_networks(physical_route()),int(settings["xray_uid"]))
    # Minimal guard used by isolated protocol tests.
    # Keep local stub DNS on loopback. DNAT of 127/8 onto a veth fails Linux's
    # loopback route checks; upstream resolver traffic still obeys the full guard.
    return f'''table inet {FULL_GUARD} {{
 chain dns {{ type nat hook output priority -101; policy accept;
  ip daddr 127.0.0.0/8 return
  ip daddr {{ 1.1.1.1, 9.9.9.9 }} return
  meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to 1.1.1.1
 }}
 chain source {{ type nat hook postrouting priority srcnat; policy accept;
  meta nfproto ipv4 oifname "{FULL_HOST}" snat ip to 172.29.247.1
 }}
 chain output {{ type filter hook output priority -30; policy drop;
  oifname "lo" accept
  meta nfproto ipv4 oifname "{FULL_HOST}" accept
  ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
 }}
 chain forward {{ type filter hook forward priority -30; policy drop;
  iifname "{HOST}" ip saddr {CLIENT} ip daddr {{ {SERVER} }} udp dport {IKE_PORT} accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 38.180.164.67 udp dport 443 accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 38.180.164.67 tcp dport {{ 24571, 24578 }} accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 195.209.211.163 tcp dport 24579 accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr {{ {SERVER} }} tcp dport 8443 accept
  oifname "{HOST}" ip daddr {CLIENT} ct state established,related accept
  meta nfproto ipv4 oifname "{FULL_HOST}" accept
  meta nfproto ipv4 iifname "{FULL_HOST}" ct state established,related accept
 }}
}}'''



def refresh_retained_guard():
    """Move only the VPN transport exception when an ingress endpoint changes."""
    if not full_guard_active():
        return
    rules = full_firewall()
    replacement = 'delete table inet '+FULL_GUARD+'\n'+rules
    command(['nft','-c','-f','-'],data=replacement)
    # Persist the closed guard before changing the active exception; a crash stays closed.
    write(ROOT/'full-guard.nft',rules)
    command(['nft','-f','-'],data=replacement)


def virtual_ip():
    data = json.loads(inside(['ip','-j','-4','addr']).stdout)
    ips = [a['local'] for link in data for a in link.get('addr_info', [])
           if ipaddress.ip_address(a['local']) in ipaddress.ip_network('10.77.0.0/24')]
    if len(ips) != 1:
        raise RuntimeError('virtual_ip_missing')
    return ips[0]


def full_namespace(address):
    vip = virtual_ip()
    if not Path('/sys/class/net/'+FULL_HOST).exists():
        command(['ip','link','add',FULL_HOST,'type','veth','peer','name',FULL_PEER])
        command(['ip','link','set',FULL_PEER,'netns',NS])
    command(['ip','addr','replace','172.29.247.1/30','dev',FULL_HOST])
    command(['ip','link','set',FULL_HOST,'mtu','1280','up'])
    inside(['ip','addr','replace','172.29.247.2/30','dev',FULL_PEER])
    inside(['ip','link','set',FULL_PEER,'mtu','1280','up'])
    inside(['sysctl','-qw','net.ipv4.conf.all.forwarding=1','net.ipv4.conf.all.rp_filter=0'])
    # StrongSwan's catch-all route must not capture replies to the host-facing interface.
    inside(['ip','rule','del','priority','90','to',FULL_NET,'lookup','main'],check=False)
    inside(['ip','rule','add','priority','90','to',FULL_NET,'lookup','main'])
    deletions = ''
    for family,table in [('inet','evn_full_forward'),('netdev','evn_full_wire')]:
        if inside(['nft','list','table',family,table],check=False).returncode == 0:
            deletions += f'delete table {family} {table}\n'
    rules = deletions + f'''table inet evn_full_forward {{
 chain forward {{ type filter hook forward priority -5; policy drop;
  iifname "{FULL_PEER}" oifname "{PEER}" ip saddr 172.29.247.1 accept
  iifname {{ "{PEER}", "lo" }} oifname "{FULL_PEER}" ip daddr 172.29.247.1 ipsec in reqid {REQID} ct state established,related accept
 }}
 chain nat {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr 172.29.247.1 oifname "{PEER}" snat ip to {vip}
 }}
}}
table netdev evn_full_wire {{
 chain egress {{ type filter hook egress device "{PEER}" priority 0; policy drop;
  ether type arp accept
  ip daddr {address} udp dport {ACTIVE['port']} accept
  ip daddr 38.180.164.67 tcp dport {{ 24571, 24578 }} accept
  ip daddr 195.209.211.163 tcp dport 24579 accept
  ip daddr {address} tcp dport 8443 accept
 }}
}}'''
    inside(['nft','-c','-f','-'],data=rules)
    inside(['nft','-f','-'],data=rules)
    # Replace the original lab forward drop; host ingress remains constrained by full_forward.
    inside(['nft','flush','chain','inet','evn_starfive_guard','forward'])
    inside(['nft','add','rule','inet','evn_starfive_guard','forward','iifname',FULL_PEER,'meta','nfproto','ipv4','accept'])
    inside(['nft','add','rule','inet','evn_starfive_guard','forward','oifname',FULL_PEER,'ipsec','in','reqid',str(REQID),'ct','state','established,related','accept'])


_EGRESS_PROBES = ('https://1.1.1.1/cdn-cgi/trace', 'https://api.ipify.org')
_egress_preferred = 0


def parse_exit(body, trace):
    values = [line[3:] for line in body.splitlines() if line.startswith('ip=')] if trace else [body.strip()]
    if len(values) != 1:
        return None
    try:
        return str(ipaddress.IPv4Address(values[0]))
    except ipaddress.AddressValueError:
        return None


def egress_health():
    """Independent HTTPS providers; a verified wrong IP must never be masked by fallback."""
    global _egress_preferred
    for index in (_egress_preferred, 1-_egress_preferred):
        url = _EGRESS_PROBES[index]
        try:
            result = inside(['curl','-4','--noproxy','*','--fail','--silent','--show-error',
                             '--connect-timeout','3','--max-time','5','--max-filesize','32768',url],timeout=7,check=False)
        except (OSError,subprocess.TimeoutExpired):
            continue
        if result.returncode != 0:
            continue
        observed = parse_exit(result.stdout, index == 0)
        if observed is not None:
            if observed != '38.180.164.67':
                return False
            _egress_preferred = index
            return True
    return False


def path_healthy(daemon):
    # The private diagnostic HTTP collector is not part of the VPN data plane.
    # Its outage/restart must not discard a working route's three-loss budget.
    return (daemon.poll() is None and installed()
            and (TLS_PROCESS is None or TLS_PROCESS.poll() is None) and egress_health())


def retire_previous_connections(addresses):
    # The firewall already blocks old non-exempt flows. Do not kill all sockets
    # sharing a physical source address: that destroys SSH, LAN and app exclusions.
    # Only this manager's DNS translations need explicit retirement (handled above).
    return


def system_dns_health(resolv_conf=Path('/etc/resolv.conf')):
    # getaddrinfo/curl may use nss-resolve over a Unix socket and miss a broken
    # UDP stub used by other applications. Exercise resolv.conf independently.
    servers = [line.split()[1] for line in resolv_conf.read_text().splitlines()
               if line.split()[:1] == ['nameserver'] and len(line.split()) >= 2][:3]
    for server in servers:
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
            transaction = secrets.token_bytes(2)
            query = transaction+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            query += b'\x03api\x05ipify\x03org\x00\x00\x01\x00\x01'
            with socket.socket(family, socket.SOCK_DGRAM) as resolver:
                resolver.settimeout(2)
                resolver.connect((server, 53))
                resolver.send(query)
                answer = resolver.recv(4096)
            if (len(answer) >= 12 and answer[:2] == transaction and
                    answer[2] & 0x80 and answer[3] & 15 == 0 and
                    int.from_bytes(answer[6:8], 'big') > 0):
                return True
        except (OSError, ValueError):
            continue
    return False


def start_namespace_dns():
    """A private DNS endpoint reachable only over the host/namespace veth."""
    global DNS_PROCESS
    if DNS_PROCESS is not None and DNS_PROCESS.poll() is None:return
    cfg = {'log':{'loglevel':'warning','access':'none'},
      'inbounds':[{'tag':'dns-in','listen':'172.29.247.2','port':53,'protocol':'dokodemo-door',
                   'settings':{'address':'1.1.1.1','port':53,'network':'tcp,udp'}}],
      'dns':{'servers':['1.1.1.1','tcp://9.9.9.9','https://1.0.0.1/dns-query'],
             'queryStrategy':'UseIPv4','tag':'dns-engine','enableParallelQuery':True},
      'outbounds':[{'tag':'wire','protocol':'freedom'},
                   {'tag':'dns','protocol':'dns','settings':{'rules':[{'qType':'1,28','action':'hijack'},{'action':'direct'}]}}],
      'routing':{'rules':[{'type':'field','inboundTag':['dns-in'],'outboundTag':'dns'},
                          {'type':'field','inboundTag':['dns-engine'],'outboundTag':'wire'}]}}
    path=ROOT/'namespace-dns.json';write(path,json.dumps(cfg))
    binary='/opt/vpn-manager/bin/xray'
    inside([binary,'run','-test','-config',path])
    DNS_PROCESS=subprocess.Popen(['ip','netns','exec',NS,binary,'run','-config',str(path)],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(30):
        if DNS_PROCESS.poll() is not None:raise RuntimeError('private_dns_stopped')
        if '172.29.247.2:53' in inside(['ss','-lnu'],check=False).stdout:
            write(Path('/etc/netns')/NS/'resolv.conf','nameserver 172.29.247.2\noptions timeout:3 attempts:2\n')
            return
        time.sleep(.1)
    raise RuntimeError('private_dns_not_ready')


def use_resolver_file(path=Path('/etc/resolv.conf')):
    data=json.loads(full_state().read_text())
    target=ROOT/'resolv-vpn.conf'
    if 'resolver_original' not in data:
        data['resolver_original']={'link':os.readlink(path) if path.is_symlink() else None,
                                   'text':path.read_text() if path.exists() else '',
                                   'existed':path.exists() or path.is_symlink()}
    data['dns_fallback']=True
    write(full_state(),json.dumps(data))
    write(target,'nameserver 172.29.247.2\noptions timeout:3 attempts:2\n')
    target.chmod(0o644)
    # The parent must be traversable by applications. Secrets remain root-only.
    # Put only this public resolver file outside the credential directory.
    public=Path('/run/evgenium-resolv.conf')
    public.parent.mkdir(parents=True,exist_ok=True)
    write(public,target.read_text());public.chmod(0o644)
    temporary=path.with_name('.evgenium-resolv.new')
    temporary.unlink(missing_ok=True);temporary.symlink_to(public)
    os.replace(temporary,path)


def restore_resolver_file(data,path=Path('/etc/resolv.conf')):
    saved=data.get('resolver_original')
    if saved and path.is_symlink() and os.readlink(path)=='/run/evgenium-resolv.conf':
        temporary=path.with_name('.evgenium-resolv.restore')
        temporary.unlink(missing_ok=True)
        if saved['link'] is not None:temporary.symlink_to(saved['link'])
        else:temporary.write_text(saved['text']);temporary.chmod(0o644)
        if saved.get('existed',True):os.replace(temporary,path)
        else:path.unlink();temporary.unlink()
    elif not saved and 'dns_backup' in data:
        path.write_text(data['dns_backup'])


def recover_system_dns():
    for _ in range(2):
        if system_dns_health():return True
        if STOP:return False
        time.sleep(.3)
    if not full_state().exists():return False
    # Switch only the resolver file we own; never stop another VPN or resolver.
    stage('repairing','Переключаю неисправный системный DNS на защищённый резерв.',90,active=False,error_code='system_dns_failed')
    use_resolver_file()
    return system_dns_health()


def persist_guard(rules):
    # Guard persistence precedes switching. Cleanup after a crash never opens the Internet.
    guard_unit = '''[Unit]
Description=Evgenium full-device kill switch
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/vpn-manager/starfive-tunnel/full-guard.nft
[Install]
WantedBy=multi-user.target
'''.replace('/usr/sbin/nft', shutil.which('nft'))
    write(ROOT/'full-guard.nft',rules)
    write(Path('/etc/systemd/system/evgenium-starfive-full-guard.service'),guard_unit)
    command(['systemctl','daemon-reload'])
    command(['systemctl','enable','evgenium-starfive-full-guard.service'])


def activate_full(address):
    old_addresses = [a['local'] for link in json.loads(command(['ip','-j','-4','addr','show','scope','global']).stdout)
                     if link.get('ifname') not in (HOST,FULL_HOST)
                     for a in link.get('addr_info',[]) if a.get('scope') == 'global']
    if not full_state().exists():
        if Path('/sys/class/net/'+FULL_HOST).exists():
            raise RuntimeError('full_interface_collision')
        if command(['ip','route','show','table',FULL_TABLE],check=False).stdout.strip():
            raise RuntimeError('full_table_collision')
        if command(['ip','route','show','table',ADMIN_TABLE],check=False).stdout.strip():
            raise RuntimeError('admin_table_collision')
        if any(r.get('priority') in (79,80) for r in json.loads(command(['ip','-j','-4','rule']).stdout)):
            raise RuntimeError('full_rule_collision')
        write(full_state(),json.dumps({'active':False}))
    full_namespace(address)
    start_namespace_dns()
    # Validate the egress filter before interrupting the previous VPN.
    if not egress_health():
        raise RuntimeError('estonia_egress_failed')
    rules = full_firewall()
    # Repair may inherit a guard from an older version. Replace our table in
    # one nft transaction, so fixes apply without opening an unguarded window.
    replacement = ('delete table inet '+FULL_GUARD+'\n' if full_guard_active() else '')+rules
    command(['nft','-c','-f','-'],data=replacement)
    command(['nft','-f','-'],data=replacement)
    persist_guard(rules)
    # This command stops only this manager's previous Xray mode and removes its guard.
    command(['/usr/local/sbin/vpnctl','internal-starfive-pause-main'],timeout=40)
    command(['ip','route','replace','unreachable','default','metric','32760','table',FULL_TABLE])
    command(['ip','route','replace','default','via','172.29.247.2','dev',FULL_HOST,'metric','10','table',FULL_TABLE])
    command(['ip','rule','del','priority','80','lookup',FULL_TABLE],check=False)
    for rule in (['priority','79','to',CLIENT+'/32','lookup','main'],
                 ['priority','79','iif',FULL_HOST,'lookup','main']):
        command(['ip','rule','del',*rule],check=False)
        command(['ip','rule','add',*rule])
    command(['ip','rule','add','priority','80','lookup',FULL_TABLE])
    data=json.loads(full_state().read_text())
    if shutil.which('resolvectl') and command(['systemctl','is-active','--quiet','systemd-resolved'],check=False).returncode == 0:
        data['dns_mode']='resolved_link'
        write(full_state(),json.dumps(data))
        command(['resolvectl','dns',FULL_HOST,'172.29.247.2'])
        command(['resolvectl','domain',FULL_HOST,'~.'])
        command(['resolvectl','default-route',FULL_HOST,'yes'])
        command(['resolvectl','flush-caches'],check=False)
    else:
        use_resolver_file()
    clear_dns_mappings(previous_vpn=True)
    retire_previous_connections(old_addresses)
    if policy is not None:
        policy.apply()
    if not recover_system_dns():
        raise RuntimeError('system_dns_failed')
    # Test the actual host path as well as namespace probes before announcing connected.
    check = command(['curl','-4','--noproxy','' if policy is not None else '*','--fail','--silent','--max-time','10',*(['--socks5-hostname','127.0.0.1:18554'] if policy is not None else []),'https://api.ipify.org'],timeout=12)
    if check.stdout.strip() != '38.180.164.67':
        raise RuntimeError('host_egress_failed')
    data=json.loads(full_state().read_text())
    data['active']=True
    write(full_state(),json.dumps(data))


def cleanup_full(release=False):
    global DNS_PROCESS
    if DNS_PROCESS is not None and DNS_PROCESS.poll() is None:
        DNS_PROCESS.terminate()
        try:DNS_PROCESS.wait(timeout=3)
        except subprocess.TimeoutExpired:DNS_PROCESS.kill();DNS_PROCESS.wait()
    DNS_PROCESS=None
    if policy is not None:
        policy.stop(release=release)
    if not full_state().exists():
        return
    data=json.loads(full_state().read_text())
    command(['ip','route','del','default','metric','10','table',FULL_TABLE],check=False)
    command(['ip','link','del',FULL_HOST],check=False)
    # On failure: retain routing, DNS and the persistent guard until explicit disconnect.
    if not release:
        return
    restore_resolver_file(data)
    command(['ip','rule','del','priority','80','lookup',FULL_TABLE],check=False)
    command(['ip','rule','del','priority','79','to',CLIENT+'/32','lookup','main'],check=False)
    command(['ip','rule','del','priority','79','iif',FULL_HOST,'lookup','main'],check=False)
    command(['ip','route','flush','table',FULL_TABLE],check=False)
    for server in ('192.168.0.163', '38.180.164.67'):
        command(['ip','rule','del','priority','79','to',server,'ipproto','tcp','dport','22','lookup',ADMIN_TABLE],check=False)
    command(['systemctl','disable','--now','evgenium-starfive-full-guard.service'],check=False)
    command(['nft','delete','table','inet',FULL_GUARD],check=False)
    clear_dns_mappings()
    clear_dns_mappings(previous_vpn=True)
    command(['ip','route','flush','table',ADMIN_TABLE],check=False)
    full_state().unlink()
    command(['resolvectl','flush-caches'],check=False) if shutil.which('resolvectl') else None


def command(args, check=True, timeout=20, data=None, env=None):
    cp = subprocess.run([str(x) for x in args], input=data, text=True, capture_output=True,
                        timeout=timeout, env=env, check=False)
    if check and cp.returncode:
        # Arguments may contain a CSR path; do not propagate process output to GUI/logs.
        raise RuntimeError('command_failed')
    return cp


def inside(args, **kwargs):
    return command(['ip', 'netns', 'exec', NS, *args], **kwargs)


def write(path, value):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)
    temporary.replace(path)


def saved():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def stage(phase, message, progress, **fields):
    data = {**saved(), 'phase': phase, 'message': message, 'progress': progress,
            'updated': int(time.time()), 'heartbeat': time.monotonic(), **fields}
    write(STATE, json.dumps(data, ensure_ascii=False))
    if support_api is not None:
        try:support_api.record(ROOT,write,data)
        except (OSError,ValueError,TypeError):pass


def status():
    data = saved()
    running = command(['systemctl', 'is-active', '--quiet', UNIT], check=False, timeout=2).returncode == 0
    if data.get('phase') == 'connected' and (not running or time.monotonic()-data.get('heartbeat', 0) > 90):
        data.update(phase='interrupted', message='Соединение остановилось. Проверьте состояние защиты и нажмите «Починить».', active=False)
    public = {key: data[key] for key in ('phase', 'message', 'progress', 'active', 'updated', 'metrics',
                                        'scope', 'since', 'retry', 'error_code', 'path') if key in data}
    token_info = token_status()
    return {'phase': 'off', 'message': ('Токен сохранён. Нажмите «Подключить».' if token_info['has_token'] else 'Введите и подтвердите токен клиента.'),
            'progress': 0, 'active': False, **public, 'running': running,
            **token_info, **device_status(), 'isolated': False, 'full_device': True, 'guard': full_guard_active(), 'protocol': 'IKEv2 → Эстония'}


@contextlib.contextmanager
def namespace():
    before = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open('/run/netns/'+NS, os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        yield
    finally:
        os.setns(before, os.CLONE_NEWNET)
        os.close(target)
        os.close(before)


def physical_route():
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'main', 'default']).stdout)
    candidates = [r for r in routes if r.get('gateway') and r.get('dev') and
                  not r['dev'].startswith(('tun', 'xray', 'wg', 'evn-'))]
    if not candidates:
        raise RuntimeError('no_physical_route')
    route = min(candidates, key=lambda r: r.get('metric', 0))
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', route['dev']):
        raise RuntimeError('invalid_interface')
    ipaddress.IPv4Address(route['gateway'])
    return route


def host_rules(iface, previous_forward=True):
    # Scope every new forwarding/NAT rule to our one interface and the configured ingress address.
    preserve_disabled = '' if previous_forward else '''  iifname "waydroid0" meta nfproto ipv4 accept
  oifname "waydroid0" meta nfproto ipv4 ct state established,related accept
  meta nfproto ipv4 drop'''
    return f'''table inet {NFT} {{
 chain forward {{
  type filter hook forward priority -20; policy accept;
  iifname "{HOST}" ip daddr {{ {SERVER} }} udp dport {IKE_PORT} accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 38.180.164.67 udp dport 443 accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 38.180.164.67 tcp dport {{ 24571, 24578 }} accept
  iifname "{HOST}" ip saddr {CLIENT} ip daddr 195.209.211.163 tcp dport 24579 accept
  iifname "{HOST}" ip daddr {{ {SERVER} }} tcp dport 8443 accept
  iifname "{HOST}" drop
  oifname "{HOST}" ip saddr {{ {SERVER}, 38.180.164.67 }} ct state established,related accept
  oifname "{HOST}" drop
{preserve_disabled}
 }}
 chain nat {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {CLIENT} oifname "{iface}" masquerade
 }}
}}'''


def setup_network():
    route = physical_route()
    # Refuse name/address collisions rather than repurposing another application's resources.
    if Path('/run/netns/'+NS).exists() or Path('/sys/class/net/'+HOST).exists() or (Path('/etc/netns')/NS).exists():
        raise RuntimeError('test_namespace_exists')
    if command(['ip', '-4', 'route', 'show', 'table', str(TABLE)], check=False).stdout.strip():
        raise RuntimeError('test_table_in_use')
    if any(NETWORK in line for line in command(['ip', '-4', 'route', 'show', 'table', 'all']).stdout.splitlines()):
        raise RuntimeError('test_network_in_use')
    old_forward = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
    # Record ownership before creating anything: cleanup is valid after every partial step.
    uplink = Path('/proc/sys/net/ipv4/conf')/route['dev']/'forwarding'
    write(ROOT/'network.json', json.dumps({'forward': old_forward, 'interface': route['dev'], 'uplink_forward': uplink.read_text().strip()}))
    command(['ip', 'netns', 'add', NS])
    write(Path('/etc/netns')/NS/'resolv.conf', 'nameserver 1.1.1.1\nnameserver 9.9.9.9\noptions timeout:2 attempts:2\n')
    # nss-resolve talks to the host daemon over a Unix socket even inside netns.
    nss=Path('/etc/nsswitch.conf').read_text()
    nss=re.sub(r'^hosts:.*$', 'hosts: files dns', nss, flags=re.M)
    write(Path('/etc/netns')/NS/'nsswitch.conf', nss)
    command(['ip', 'link', 'add', HOST, 'type', 'veth', 'peer', 'name', PEER])
    command(['ip', 'link', 'set', PEER, 'netns', NS])
    command(['ip', 'addr', 'add', GATEWAY+'/30', 'dev', HOST])
    command(['ip', 'link', 'set', HOST, 'up'])
    inside(['ip', 'addr', 'add', CLIENT+'/30', 'dev', PEER])
    inside(['ip', 'link', 'set', PEER, 'up'])
    inside(['ip', 'link', 'set', 'lo', 'up'])
    inside(['ip', 'route', 'add', 'default', 'via', GATEWAY])
    # A reconnect creates a NEW TCP socket after IKE installs its default route.
    # Keep the relay socket on the namespace uplink with the physical veth source;
    # otherwise source selection gives it the VPN VIP and tunnels it into itself.
    if ACTIVE.get('transport_address'):
        inside(['ip','rule','add','priority','89','to',ACTIVE['transport_address']+'/32',
                'ipproto','tcp','dport',str(ACTIVE['transport_port']),'lookup','main'])
    command(['ip', 'route', 'add', 'table', str(TABLE), 'default', 'via', route['gateway'], 'dev', route['dev']])
    for address in ENDPOINTS:
        command(['ip', 'rule', 'add', 'priority', str(PRIORITY), 'from', CLIENT+'/32',
                 'to', address+'/32', 'lookup', str(TABLE)])
    rules = host_rules(route['dev'], previous_forward=old_forward == '1')
    command(['nft', '-c', '-f', '-'], data=rules)
    command(['nft', '-f', '-'], data=rules)
    # Per-interface forwarding avoids ip_forward's global defaults reset.
    (Path('/proc/sys/net/ipv4/conf')/HOST/'forwarding').write_text('1\n')
    uplink.write_text('1\n')


def cleanup():
    cleanup_full()
    # An unowned namespace/table must never be deleted by a generic cleanup call.
    if not (ROOT/'network.json').exists():
        return
    data = json.loads((ROOT/'network.json').read_text())
    command(['nft', 'delete', 'table', 'inet', NFT], check=False)
    for address in (*ENDPOINTS, *LEGACY_ENDPOINTS):
        command(['ip', 'rule', 'del', 'priority', str(PRIORITY), 'from', CLIENT+'/32',
                 'to', address+'/32', 'lookup', str(TABLE)], check=False)
    for address in data.get('measurement_ips', []):
        if ipaddress.ip_address(address).is_global:
            command(['ip', 'rule', 'del', 'priority', '111', 'from', CLIENT+'/32', 'to', address+'/32', 'lookup', str(TABLE)], check=False)
    command(['ip', 'route', 'flush', 'table', str(TABLE)], check=False)
    command(['ip', 'netns', 'del', NS], check=False)
    command(['ip', 'link', 'del', HOST], check=False)
    if 'uplink_forward' in data:
        path = Path('/proc/sys/net/ipv4/conf')/data['interface']/'forwarding'
        if path.exists():
            path.write_text(data['uplink_forward']+'\n')
    elif data.get('forward') == '0' and Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1':
        Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    (Path('/etc/netns')/NS/'resolv.conf').unlink(missing_ok=True)
    (Path('/etc/netns')/NS/'nsswitch.conf').unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        (Path('/etc/netns')/NS).rmdir()
    (ROOT/'network.json').unlink(missing_ok=True)




def tls_request(address, path, body=None, client=False, timeout=8, identity=SERVER):
    context = ssl.create_default_context(cadata=PINNED_CA)
    if client:
        context.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
    sock = socket.create_connection((address, 8443), timeout=timeout)
    try:
        tls = context.wrap_socket(sock, server_hostname=identity)
    except BaseException:
        sock.close()
        raise
    connection = http.client.HTTPConnection(address, 8443, timeout=timeout)
    connection.sock = tls
    encoded = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
    try:
        connection.request('POST' if body is not None else 'GET', path, body=encoded,
                           headers={'Content-Type': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(20001)
        if response.status != 200 or len(raw) > 20000:
            raise RuntimeError('request_rejected')
        return json.loads(raw)
    finally:
        connection.close()


def enroll():
    token = (ROOT/'token').read_text().strip()
    if not re.fullmatch(TOKEN_PATTERN, token):
        raise RuntimeError('invalid_token')
    try:
        cached = json.loads((ROOT/'profile.json').read_text())
        if (cached.get('ca') == PINNED_CA and cached.get('server') == SERVER and
            re.fullmatch(r'device-[a-f0-9]{24}', cached.get('identity', '')) and
            cached.get('endpoint') in ENDPOINTS and cached.get('physical_network') and
            command(['openssl', 'x509', '-in', ROOT/'client.pem', '-checkend', str(7*86400), '-noout'], check=False).returncode == 0):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
            route = physical_route()
            current = hashlib.sha256(json.dumps({key: route.get(key) for key in ('dev', 'gateway', 'prefsrc')}, sort_keys=True).encode()).hexdigest()
            address = cached['endpoint'] if cached.get('physical_network') == current else SERVER
            return cached['identity'], address
    except (OSError, ValueError, ssl.SSLError):
        pass
    stage('token', 'Получаю сертификат для этого устройства.', 25)
    if not (ROOT/'client-key.pem').exists():
        command(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
                 '-out', ROOT/'client-key.pem'], timeout=30)
        (ROOT/'client-key.pem').chmod(0o600)
    if not (ROOT/'device').exists():
        write(ROOT/'device', secrets.token_hex(16))
    command(['openssl', 'req', '-new', '-key', ROOT/'client-key.pem', '-subj', '/CN=evgenium-device',
             '-out', ROOT/'request.pem'])
    payload = {'token': token, 'device': (ROOT/'device').read_text().strip(), 'csr': (ROOT/'request.pem').read_text()}
    last = None
    for address in (SERVER,):
        try:
            with namespace():
                reply = tls_request(address, '/enroll', payload, timeout=6)
            profile = reply.get('profile', {})
            if reply.get('ok') is not True or profile.get('ca') != PINNED_CA or profile.get('server') != SERVER:
                raise RuntimeError('invalid_profile')
            if not re.fullmatch(r'device-[a-f0-9]{24}', profile.get('identity', '')):
                raise RuntimeError('invalid_identity')
            write(ROOT/'client.pem', profile['certificate'])
            write(ROOT/'ca.pem', PINNED_CA)
            write(ROOT/'x509'/'client.pem', profile['certificate'])
            write(ROOT/'x509ca'/'ca.pem', PINNED_CA)
            write(ROOT/'private'/'client-key.pem', (ROOT/'client-key.pem').read_text())
            command(['openssl', 'verify', '-purpose', 'sslclient', '-CAfile', ROOT/'ca.pem', ROOT/'client.pem'])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
            route = physical_route()
            fingerprint = hashlib.sha256(json.dumps({key: route.get(key) for key in ('dev', 'gateway', 'prefsrc')}, sort_keys=True).encode()).hexdigest()
            write(ROOT/'profile.json', json.dumps({**profile, 'endpoint': address, 'physical_network': fingerprint}))
            return profile['identity'], address
        except (OSError, ssl.SSLError, RuntimeError) as exc:
            last = exc
    raise RuntimeError('enrollment_unavailable') from last


def daemon_configs(identity, address):
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    includes = '\n'.join('include '+str(p) for pattern in ('/etc/strongswan.d/charon/*.conf', '/etc/strongswan/strongswan.d/charon/*.conf')
                         for p in Path('/').glob(pattern.lstrip('/')))
    write(ROOT/'strongswan.conf', f'''charon {{
 load_modular = yes
 install_routes = yes
 routing_table = 51822
 routing_table_prio = 100
 plugins {{
{includes}
  vici {{ socket = unix://{RUNTIME}/charon.vici }}
  resolve {{ load = no }}
  kernel-libipsec {{ load = no }}
 }}
}}
charon-systemd {{ journal {{ default = 0; ike = 1 }} }}
''')
    # Absolute credentials are local to this device, not shared by the account token.
    write(ROOT/'connection.conf', f'''connections {{
 starfive {{
  version = 2
  remote_addrs = {address}
  remote_port = {ACTIVE['port']}
  local_port = 4500
  vips = 0.0.0.0
  proposals = aes256gcm16-prfsha384-ecp384
  encap = yes
  fragmentation = yes
  mobike = yes
  dpd_delay = 15s
  local {{ auth = eap-tls; id = {identity}; eap_id = {identity}; certs = {ROOT}/client.pem }}
  remote {{ auth = pubkey; id = {ACTIVE['identity']}; cacerts = {ROOT}/ca.pem }}
  children {{
   starfive-net {{
    local_ts = dynamic
    remote_ts = 0.0.0.0/0
    reqid = {REQID}
    esp_proposals = chacha20poly1305
    dpd_action = clear
    start_action = none
   }}
  }}
 }}
}}
secrets {{ private-client {{ file = {ROOT}/client-key.pem }} }}
''')
    # StrongSwan config uses newlines, not semicolon separators (normalize compact blocks).
    for name in ('strongswan.conf', 'connection.conf'):
        path = ROOT/name
        path.write_text(path.read_text().replace('; ', '\n').replace('{ ', '{\n').replace(' }', '\n}'))
    rules = f'''table inet evn_starfive_guard {{
 chain output {{
  type filter hook output priority -10; policy drop;
  oifname "lo" accept
  ip daddr 127.0.0.1 udp dport 24573 accept
  oifname "{FULL_PEER}" ip daddr 172.29.247.1 meta l4proto {{ tcp, udp }} th sport 53 accept
  ip daddr {address} udp dport {ACTIVE['port']} accept
  ip daddr 38.180.164.67 tcp dport {{ 24571, 24578 }} accept
  ip daddr 195.209.211.163 tcp dport 24579 accept
  meta skuid 0 ip daddr {address} tcp dport 8443 accept
  meta nfproto ipv4 ipsec out reqid {REQID} accept
 }}
 chain forward {{ type filter hook forward priority -10; policy drop; }}
}}'''
    inside(['nft', '-c', '-f', '-'], data=rules)
    inside(['nft', '-f', '-'], data=rules)


def swan(*args, timeout=15, check=True):
    return inside(['swanctl', *args, '--uri', 'unix://'+str(RUNTIME/'charon.vici')], timeout=timeout, check=check)


def installed():
    try:
        result = swan('--list-sas', '--raw', timeout=3, check=False)
        return result.returncode == 0 and 'state=ESTABLISHED' in result.stdout and 'state=INSTALLED' in result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def health():
    with namespace():
        return tls_request(HEALTH, '/health', client=True, identity=ACTIVE['identity'], timeout=3).get('service') == 'evgenium-starfive'


def download(size=1048576):
    # A bounded integrity check, not a claim to have measured the ISP's maximum rate.
    block = hashlib.shake_256(b'evgenium-starfive-integrity-v1').digest(65536)
    expected = hashlib.sha256((block*(size//len(block)+1))[:size]).hexdigest()
    context = ssl.create_default_context(cadata=PINNED_CA)
    context.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
    with namespace():
        sock = socket.create_connection((HEALTH, 8443), timeout=10)
        tls = context.wrap_socket(sock, server_hostname=ACTIVE['identity'])
        connection = http.client.HTTPConnection(HEALTH, 8443, timeout=10); connection.sock = tls
        try:
            start = time.monotonic()
            connection.request('GET', '/blob?size='+str(size))
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError('transfer_http')
            digest = hashlib.sha256(); received = 0
            while received < size:
                data = response.read(min(65536, size-received))
                if not data:
                    break
                digest.update(data); received += len(data)
            elapsed = time.monotonic()-start
        finally:
            connection.close()
    if received != size or digest.hexdigest() != expected:
        raise RuntimeError('integrity_failed')
    return {'bytes': received, 'download_mbps': round(received*8/elapsed/1e6, 2),
            'elapsed_ms': round(elapsed*1000), 'integrity': True, 'limited_sample': True}


def device_status():
    try:
        info=json.loads((ROOT/'device-info.json').read_text())
        return {'device_name':info.get('name',''),'device_number':info.get('number'),
                'device_name_pending':bool(info.get('pending') or info.get('sync_error'))}
    except (OSError,ValueError):return {'device_name':'','device_number':None,'device_name_pending':False}


def sync_device_name(name=None):
    import unicodedata
    if not token_status()['has_token']:raise ValueError('Сначала подтвердите токен клиента.')
    if name is not None:
        name=unicodedata.normalize('NFC',str(name)).strip()
        if not 1<=len(name)<=64 or any(unicodedata.category(c).startswith('C') for c in name):
            raise ValueError('Имя должно содержать от 1 до 64 обычных символов.')
    if not (ROOT/'device').exists():write(ROOT/'device',secrets.token_hex(16))
    try:info=json.loads((ROOT/'device-info.json').read_text())
    except (OSError,ValueError):info={}
    if name is not None:info.update(name=name,pending=True)
    payload={'token':(ROOT/'token').read_text().strip(),'device':(ROOT/'device').read_text().strip()}
    if info.get('pending'):payload['name']=info['name']
    try:
        with namespace() if Path('/run/netns/'+NS).exists() else contextlib.nullcontext():
            reply=tls_request(SERVER,'/device',payload,timeout=5)
        value=reply['device'];number=int(value['number'])
        if not isinstance(value['name'],str) or not 1<=len(value['name'])<=64 or number<1:raise ValueError('invalid_device_metadata')
        info={'name':value['name'],'number':number,'pending':False,'sync_error':False}
    except (OSError,RuntimeError,ValueError,KeyError,http.client.HTTPException):
        info['sync_error']=True
    write(ROOT/'device-info.json',json.dumps(info,ensure_ascii=False))
    return device_status()


def token_status():
    try:
        token = (ROOT/'token').read_text().strip()
    except FileNotFoundError:
        token = ''
    valid = re.fullmatch(TOKEN_PATTERN, token) is not None
    return {'has_token': valid,
            'token_hint': 'EVN1-•••• · ID ' + hashlib.sha256(token.encode()).hexdigest()[:8] if valid else ''}


def save_token(token):
    token = token.strip()
    if not re.fullmatch(TOKEN_PATTERN, token):
        raise ValueError('Нужен токен клиента формата EVN1-…')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = (ROOT/'token').read_text().strip() if (ROOT/'token').exists() else ''
    if old == token:
        sync_device_name();return
    if command(['systemctl', 'is-active', '--quiet', UNIT], check=False).returncode == 0:
        raise RuntimeError('Сначала отключите VPN-туннель перед сменой токена.')
    # A different account needs its own device credentials. Never reuse its certificate.
    for name in ('device-info.json', 'device', 'client-key.pem', 'client.pem', 'profile.json', 'request.pem',
                 'private/client-key.pem', 'x509/client.pem', 'ranking.json', 'recalibrate', 'events.json', 'support-preview.json'):
        (ROOT/name).unlink(missing_ok=True)
    write(ROOT/'token', token)
    sync_device_name()
    stage('off', 'Токен сохранён. Нажмите «Подключить».', 0, active=False, metrics={})


def connect(token='', repair=False):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if token:
        save_token(token)
    if not token_status()['has_token']:
        raise ValueError('Введите и подтвердите токен клиента.')
    ensure_dependencies()
    if repair:
        write(ROOT/'recalibrate', '1')
    unit = f'''[Unit]
Description=Evgenium full-device Estonia VPN
After=network.target
StartLimitIntervalSec=180
StartLimitBurst=3
[Service]
Type=simple
ExecStart=/usr/local/sbin/vpnctl internal-starfive-tunnel
ExecStopPost=/usr/local/sbin/vpnctl internal-starfive-tunnel-cleanup
TimeoutStopSec=20
KillMode=mixed
UMask=0077
MemoryMax=256M
Restart=on-failure
RestartSec=3
'''
    write(Path('/etc/systemd/system')/UNIT, unit)
    recovery = "evgenium-starfive-tunnel-recover.service"
    write(Path('/etc/systemd/system')/recovery, """[Unit]
Description=Recover only interrupted Evgenium tunnel test resources
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target vpn-xray.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpnctl internal-starfive-tunnel-cleanup
[Install]
WantedBy=multi-user.target
""")
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', recovery])
    command(['systemctl','reset-failed',UNIT],check=False)
    stage('starting' , 'Готовлю подключение в Эстонию.', 2, active=False, retry=0, error_code='')
    command(['systemctl', 'restart' if repair else 'start', UNIT])
    print('VPN запускается.',flush=True)


def disconnect():
    command(['systemctl', 'stop', UNIT], check=False, timeout=25)
    cleanup()
    cleanup_full(release=True)
    stage('off', 'VPN выключен.', 0, active=False)
    print('VPN выключен.')


def start_daemon(env):
    (RUNTIME/'charon.vici').unlink(missing_ok=True)
    log = (ROOT/'charon.log').open('w')
    daemon = subprocess.Popen(['ip', 'netns', 'exec', NS, charon_binary()],
                              env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    log.close()
    try:
        for _ in range(60):
            if STOP or daemon.poll() is not None:
                raise RuntimeError('daemon_stopped')
            if (RUNTIME/'charon.vici').exists() and swan('--stats', check=False, timeout=1).returncode == 0:
                break
            time.sleep(.1)
        swan('--load-creds', '--noprompt', '--file', ROOT/'connection.conf')
        swan('--load-conns', '--file', ROOT/'connection.conf')
        return daemon
    except BaseException:
        stop_process(daemon)
        raise


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)


def stop_candidate(daemon=None):
    global TLS_PROCESS
    stop_process(daemon)
    stop_process(TLS_PROCESS);TLS_PROCESS=None
    cleanup()


def prepare_data_plane(address):
    if not full_state().exists():
        if Path('/sys/class/net/'+FULL_HOST).exists():
            raise RuntimeError('full_interface_collision')
        if command(['ip','route','show','table',FULL_TABLE],check=False).stdout.strip():
            raise RuntimeError('full_table_collision')
        if command(['ip','route','show','table',ADMIN_TABLE],check=False).stdout.strip():
            raise RuntimeError('admin_table_collision')
        if any(r.get('priority') in (79,80) for r in json.loads(command(['ip','-j','-4','rule']).stdout)):
            raise RuntimeError('full_rule_collision')
        write(full_state(),json.dumps({'active':False,'measurement_only':True}))
    full_namespace(address)
    start_namespace_dns()


def start_candidate(candidate,identity):
    global ACTIVE,TLS_PROCESS
    ACTIVE=candidate
    write(ROOT/'active-path.json',json.dumps({'id':candidate['id']}))
    setup_network()
    daemon_configs(identity,candidate['address'])
    if candidate['tls'] or candidate.get('evgt'):
        if candidate.get('evgt'):
            binary=ensure_evgt_binary()
            carrier=[str(binary),'-mode','client','-server',candidate.get('transport_address',candidate['address'])+':'+str(candidate.get('transport_port',24578)),'-server-name',candidate['identity'],
                     '-udp-listen','127.0.0.1:24573','-udp-peer',CLIENT+':4500',
                     '-ca',str(ROOT/'ca.pem'),'-cert',str(ROOT/'client.pem'),'-key',str(ROOT/'client-key.pem')]
        else:carrier=['/usr/local/sbin/vpnctl','internal-tls-client']
        TLS_PROCESS=subprocess.Popen(['ip','netns','exec',NS,*carrier],
                                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                     stderr=None if candidate.get('evgt') else subprocess.DEVNULL)
        for _ in range(50):
            if STOP:raise RuntimeError('cancelled')
            if TLS_PROCESS.poll() is not None:raise RuntimeError('tls_carrier_stopped')
            if '127.0.0.1:24573' in inside(['ss','-anu'],check=False).stdout:break
            time.sleep(.1)
        else:raise RuntimeError('tls_carrier_not_ready')
        inside(['nft','-f','-'],data='table ip evn_tls_carrier {\n chain output {\n type nat hook output priority dstnat; policy accept;\n ip daddr 38.180.164.67 udp dport 443 redirect to :24573\n }\n}\n')
    env={**os.environ,'STRONGSWAN_CONF':str(ROOT/'strongswan.conf')};env.pop('NOTIFY_SOCKET',None)
    daemon=start_daemon(env)
    try:
        swan('--initiate','--child','starfive-net',timeout=35)
        if STOP:raise RuntimeError('cancelled')
        if not installed():raise RuntimeError('handshake_failed')
        prepare_data_plane(candidate['address'])
        if not egress_health():raise RuntimeError('estonia_egress_failed')
        return daemon
    except BaseException:
        stop_process(daemon);raise


def speed_sample(size=2097152):
    """Bounded synthetic bidirectional probe; never reads user files."""
    payload=ROOT/'speed-payload.bin'
    if not payload.exists() or payload.stat().st_size!=size:
        with payload.open('wb') as f:
            for _ in range(size//65536):f.write(secrets.token_bytes(65536))
        payload.chmod(0o600)
    base=['curl','-4','--noproxy','*','--fail','--silent','--show-error','--connect-timeout','3','--max-time','12',
          '--output','/dev/null','--write-out','%{http_code} %{size_download} %{size_upload} %{time_total} %{time_connect}']
    results=[]
    for direction in ('down','up'):
        if STOP:raise RuntimeError('cancelled')
        extra=['https://speed.cloudflare.com/__down?bytes='+str(size)] if direction=='down' else ['--data-binary','@'+str(payload),'https://speed.cloudflare.com/__up']
        r=inside(base+extra,timeout=14,check=False)
        try:
            code,down,up,elapsed,latency=r.stdout.split()
            count=float(down if direction=='down' else up)
            if r.returncode or code!='200' or count<size:raise ValueError()
            results.append((count*8/max(.001,float(elapsed))/1e6,float(latency)*1000))
        except (ValueError,TypeError):return {'available':False}
    return {'available':True,'download_mbps':round(results[0][0],2),'upload_mbps':round(results[1][0],2),
            'latency_ms':round(max(x[1] for x in results),1),'sample_bytes':size}


def traffic_total():
    try:
        stats=Path('/sys/class/net')/FULL_HOST/'statistics'
        return sum(int((stats/name).read_text()) for name in ('rx_bytes','tx_bytes'))
    except (OSError,ValueError):return 0


def speed_degraded(sample,baseline):
    # Require usable samples and a meaningful baseline in the affected direction.
    return bool(sample.get('available') and any(
        baseline.get(k,0)>=2 and sample.get(k,0)<baseline[k]*.2
        for k in ('download_mbps','upload_mbps')))


def worker():
    global STOP
    STOP=False
    signal.signal(signal.SIGTERM,lambda *_:globals().__setitem__('STOP',True))
    signal.signal(signal.SIGINT,lambda *_:globals().__setitem__('STOP',True))
    daemon=None
    rank=rank_api.Ranking(ROOT/'ranking.json',[x['id'] for x in CANDIDATES])
    try:
        cleanup();refresh_retained_guard()
        stage('prepare','Готовлю защищённые маршруты.',5,active=False,metrics={},error_code='',scope='full-device')
        setup_network()
        identity,_=enroll()
        sync_device_name()
        cleanup()
        loaded=rank.load()
        rebuild=(ROOT/'recalibrate').exists()
        if not rebuild and (not loaded or not rank.candidates()):
            rank.bootstrap()
        if rebuild:
            measurements={}
            for i,candidate in enumerate(CANDIDATES):
                if STOP:return
                stage('ranking','Проверяю маршрут: '+candidate['label'],10+int(i*60/len(CANDIDATES)),active=False,path=candidate['id'])
                try:
                    daemon=start_candidate(candidate,identity)
                    try:
                        integrity=download(1048576)['integrity']
                    except RuntimeError as error:
                        if str(error)=='integrity_failed':raise
                        integrity=None
                    except (OSError,ValueError,subprocess.TimeoutExpired):
                        integrity=None
                    measurements[candidate['id']]={'ok':True,**speed_sample(2097152),'integrity':integrity}
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                    if STOP:return
                    measurements[candidate['id']]={'ok':False}
                finally:
                    stop_candidate(daemon);daemon=None
            rank.build(measurements)
            (ROOT/'recalibrate').unlink(missing_ok=True)
        candidates={x['id']:x for x in CANDIDATES}
        current=next(iter(rank.candidates()),None)
        while current and not STOP:
            candidate=candidates[current]
            try:
                stage('handshake','Подключаю: '+candidate['label'],75,active=False,path=current)
                daemon=start_candidate(candidate,identity)
                stage('routing','Подключаю трафик к проверенному маршруту.',92)
                activate_full(candidate['address'])
                stage('connected','Подключено: '+candidate['label']+'.',100,active=True,path=current,
                      metrics=rank.data['entries'][current],since=int(time.time()),error_code='')
                failures=0;slow=0;last_traffic=traffic_total();next_speed=time.monotonic()+600+secrets.randbelow(60)
                while not STOP:
                    for _ in range(50):
                        if STOP:break
                        time.sleep(.1)
                    if STOP:break
                    try:
                        if policy is not None:policy.ensure_route()
                        if DNS_PROCESS is None or DNS_PROCESS.poll() is not None:
                            stage('repairing','Перезапускаю защищённый DNS.',90,active=False,error_code='private_dns_stopped')
                            start_namespace_dns()
                        healthy=path_healthy(daemon)
                        if healthy and not recover_system_dns():raise RuntimeError('system_dns_failed')
                    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):healthy=False
                    failures=0 if healthy else failures+1
                    if failures>=2:raise RuntimeError('path_health_failed')
                    if not healthy:
                        stage('checking','Ответ задерживается. Проверяю текущий маршрут.',90,active=False)
                        continue
                    if time.monotonic()>=next_speed:
                        traffic=traffic_total()
                        if not slow and traffic-last_traffic<4194304:
                            last_traffic=traffic;next_speed=time.monotonic()+600+secrets.randbelow(60)
                            continue
                        last_traffic=traffic
                        sample=speed_sample(2097152);baseline=rank.data['entries'][current]
                        degraded=speed_degraded(sample,baseline)
                        slow=slow+1 if degraded else 0
                        next_speed=time.monotonic()+(20 if slow else 600+secrets.randbelow(60))
                        if slow>=3:raise RuntimeError('confirmed_speed_drop')
                    stage('connected','Подключено: '+candidate['label']+'.',100,active=True,path=current,error_code='')
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
                if STOP:break
                reason=str(exc) if re.fullmatch('[a-z_]{1,64}',str(exc)) else 'connection_failed'
                # A missing physical interface is not a transport's defeat.
                try:
                    route=physical_route();carrier=Path('/sys/class/net')/route['dev']/'carrier'
                    offline=carrier.exists() and carrier.read_text().strip()=='0'
                except (OSError,RuntimeError):offline=True
                if not offline:
                    rank.lose(current,reason)
                    following=rank.next_after(current)
                    current=following or next(iter(rank.candidates()),None)
                stage('repairing','Связь потеряна. Переключаю защищённый маршрут.' if not offline else 'Ожидаю восстановления физической сети.',65,
                      active=False,error_code=reason)
                for _ in range(30 if not offline else 100):
                    if STOP:break
                    time.sleep(.1)
            finally:
                stop_candidate(daemon);daemon=None
        if not STOP:
            stage('failed','Доступные маршруты исчерпали три попытки. Нажмите «Восстановить» для нового рейтинга.',0,
                  active=False,error_code='ranking_exhausted')
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
        if not STOP:
            code=str(exc) if re.fullmatch('[a-z_]{1,64}',str(exc)) else 'connection_failed'
            stage('failed','Не удалось подготовить VPN. Нажмите «Восстановить».',0,active=False,error_code=code)
    finally:
        stop_candidate(daemon)
        if STOP:stage('off','VPN выключен.',0,active=False)
