"""One isolated Russia-to-Russia IKEv2 test tunnel. Never controls the working Xray."""
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
import ssl
import subprocess
import time

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
PRIORITY = 110
NFT = 'evgenium_starfive_lab_host'
SERVER = '109.194.67.159'
SERVER_LAN = '192.168.0.163'
HEALTH = '10.77.0.1'
REQID = 177
TOKEN_PATTERN = r'EVN1-[A-Za-z0-9_-]{43}'
STOP = False
PINNED_CA = '-----BEGIN CERTIFICATE-----\nMIIEODCCAqCgAwIBAgIUbkJ+8SaqAgwY1RDAjZRTjcqQ9eMwDQYJKoZIhvcNAQEL\nBQAwIjEgMB4GA1UEAwwXRXZnZW5pdW0gcHJpdmF0ZSBWUE4gQ0EwHhcNMjYxMDA3\nMTkxMzQxWhcNMzYxMDA0MTkxMzQxWjAiMSAwHgYDVQQDDBdFdmdlbml1bSBwcml2\nYXRlIFZQTiBDQTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAOZ+nviE\n2OrF7Pdtkk/XIaFVIvJlvC11VZf9rljCBIvBykbsrArGryQHGnuuXLNaaS8NtLxY\nNeSBDK6MdgYJAejsP4wITub3nMjSG2umIIVU6mE+GDozGPlNMNJ+bhkKaVhaPjFE\nyYLYrdPe5VA4w+5p0NZOD6CBHD3tEXWBNRIeVSWbtMITsOES1Pe/aAL7v3oNIVkV\n8nDw9j7+wG2y5dhbp7KUJHbrDB024r7cYrQ3axYF6gykjmztpKXsbkxQv27BvhSB\ne0EktJ/jCS6R9IImYgIQrCraWZmVScnGF/Aq4TNw1H4OzFCkR+7JUlYnSYUvMRi1\nLzKekUC+2/0WFmhnCoDtdjcoYbxpLpKDelGiS3RsNCvxnslMaPz5hCcF64Y7RijX\nj6DuCYpFYWlr13B20qAnRoUas+AjX7PXCkR4xOhH+kW8/HmFHiHkohWE0wllISBX\nVBo7KBOZd8SVewybd2rB4soXouTtjXs/jTge+HWxQDGPP1umfz8cFLR/uQIDAQAB\no2YwZDAdBgNVHQ4EFgQUoQfTif77xWt06haXh3ha890qkT8wHwYDVR0jBBgwFoAU\noQfTif77xWt06haXh3ha890qkT8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B\nAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggGBAI7GKnmfJjuL1QvyRtlw+Hr6AY/Z\nOxdDvECefoFL7Q41VZa+L7DI87kMLYHygRHush66oUv878TWMtasnbt/8wYg6jrw\nAygpg/F3VD24yTrnJ7OCdyGib6LGuusuTP4rUGsccWcznQXYFkzRVz1VeYMZUN+P\ntAViNl4ERS1fh+cGzT4OqXQkJDkReqH/HCTE8kUQUUgXaSXphKjGa8pR2HVeFukX\n+0pp1iR+6di4aCKapkaTiVR3r62tRBUwbxoFYRyxNXynTK9EhnM25WEpn/qu0lsD\noXrFVmj0AQfAUHRN/2rPL//w6RPEpHgUcrt7zuSgoXJZh0DT30VEIK9NNbuKSFd9\nIiWvrxbVQS6mQgtEZN4Lc2Hm1pvY+WrI+H03u8042+cpLIsCnxPm9Wvi7dMXxqob\no2/aL2xDG5G/8WVR/W5EAfvKdxdrk3H602occov7+Jg1voxi00IbdMExoMxd5aeh\nfXRiJhTEFouIpmESCF4vVMlWFr3mqlQ3GKSPVA==\n-----END CERTIFICATE-----\n'


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


def status():
    data = saved()
    running = command(['systemctl', 'is-active', '--quiet', UNIT], check=False, timeout=2).returncode == 0
    if data.get('phase') == 'connected' and (not running or time.monotonic()-data.get('heartbeat', 0) > 45):
        data.update(phase='interrupted', message='Тестовый туннель остановился. Рабочий VPN сохранён.', active=False)
    public = {key: data[key] for key in ('phase', 'message', 'progress', 'active', 'updated', 'metrics',
                                        'scope', 'since', 'retry') if key in data}
    token_info = token_status()
    return {'phase': 'off', 'message': ('Токен сохранён. Нажмите «Подключить».' if token_info['has_token'] else 'Введите и подтвердите токен клиента.'),
            'progress': 0, 'active': False, **public, 'running': running,
            **token_info, 'isolated': True, 'protocol': 'IKEv2'}


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
    # Scope every new forwarding/NAT rule to our one interface and two server addresses.
    preserve_disabled = '' if previous_forward else '  meta nfproto ipv4 drop'
    return f'''table inet {NFT} {{
 chain forward {{
  type filter hook forward priority -20; policy accept;
  iifname "{HOST}" ip daddr {{ {SERVER}, {SERVER_LAN} }} udp dport {{ 500, 4500 }} accept
  iifname "{HOST}" ip daddr {{ {SERVER}, {SERVER_LAN} }} tcp dport 8443 accept
  iifname "{HOST}" drop
  oifname "{HOST}" ip saddr {{ {SERVER}, {SERVER_LAN} }} ct state established,related accept
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
    write(Path('/etc/netns')/NS/'resolv.conf', 'nameserver 77.88.8.8\nnameserver 77.88.8.1\noptions timeout:2 attempts:2\n')
    command(['ip', 'link', 'add', HOST, 'type', 'veth', 'peer', 'name', PEER])
    command(['ip', 'link', 'set', PEER, 'netns', NS])
    command(['ip', 'addr', 'add', GATEWAY+'/30', 'dev', HOST])
    command(['ip', 'link', 'set', HOST, 'up'])
    inside(['ip', 'addr', 'add', CLIENT+'/30', 'dev', PEER])
    inside(['ip', 'link', 'set', PEER, 'up'])
    inside(['ip', 'link', 'set', 'lo', 'up'])
    inside(['ip', 'route', 'add', 'default', 'via', GATEWAY])
    command(['ip', 'route', 'add', 'table', str(TABLE), 'default', 'via', route['gateway'], 'dev', route['dev']])
    for address in (SERVER, SERVER_LAN):
        command(['ip', 'rule', 'add', 'priority', str(PRIORITY), 'from', CLIENT+'/32',
                 'to', address+'/32', 'lookup', str(TABLE)])
    rules = host_rules(route['dev'], previous_forward=old_forward == '1')
    command(['nft', '-c', '-f', '-'], data=rules)
    command(['nft', '-f', '-'], data=rules)
    # Per-interface forwarding avoids ip_forward's global defaults reset.
    (Path('/proc/sys/net/ipv4/conf')/HOST/'forwarding').write_text('1\n')
    uplink.write_text('1\n')


def cleanup():
    # An unowned namespace/table must never be deleted by a generic cleanup call.
    if not (ROOT/'network.json').exists():
        return
    data = json.loads((ROOT/'network.json').read_text())
    command(['nft', 'delete', 'table', 'inet', NFT], check=False)
    for address in (SERVER, SERVER_LAN):
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
    with contextlib.suppress(OSError):
        (Path('/etc/netns')/NS).rmdir()
    (ROOT/'network.json').unlink(missing_ok=True)


@contextlib.contextmanager
def measurement_route(address):
    """A short-lived direct route for a verified Yandex HTTPS measurement, lab only."""
    if not ipaddress.ip_address(address).is_global or address in (SERVER, SERVER_LAN):
        raise ValueError('invalid_measurement_address')
    label = 'evn-measure-'+secrets.token_hex(8)
    data = json.loads((ROOT/'network.json').read_text())
    data['measurement_ips'] = sorted(set(data.get('measurement_ips', [])+[address]))
    write(ROOT/'network.json', json.dumps(data))
    try:
        command(['ip', 'rule', 'add', 'priority', '111', 'from', CLIENT+'/32',
                 'to', address+'/32', 'lookup', str(TABLE)])
        command(['nft', 'insert', 'rule', 'inet', NFT, 'forward', 'iifname', HOST,
                 'ip', 'daddr', address, 'tcp', 'dport', '443', 'accept', 'comment', label])
        command(['nft', 'insert', 'rule', 'inet', NFT, 'forward', 'oifname', HOST,
                 'ip', 'saddr', address, 'ct', 'state', 'established,related', 'accept', 'comment', label])
        yield
    finally:
        result = command(['nft', '-j', '-a', 'list', 'chain', 'inet', NFT, 'forward'], check=False)
        if result.returncode == 0:
            for entry in json.loads(result.stdout).get('nftables', []):
                rule = entry.get('rule', {})
                if rule.get('comment') == label:
                    command(['nft', 'delete', 'rule', 'inet', NFT, 'forward', 'handle', str(rule['handle'])], check=False)
        command(['ip', 'rule', 'del', 'priority', '111', 'from', CLIENT+'/32',
                 'to', address+'/32', 'lookup', str(TABLE)], check=False)


def provider_addresses(host):
    # DNS may use the working resolver, but measured HTTPS itself takes the physical route.
    addresses = [answer[4][0] for answer in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)]
    return list(dict.fromkeys(x for x in addresses if ipaddress.ip_address(x).is_global))[:2]


def provider_get(host, path, maximum, measure=False):
    last = None
    for address in provider_addresses(host):
        output = ROOT/('reference-'+secrets.token_hex(8)+'.tmp')
        try:
            with measurement_route(address):
                args = ['curl', '-4', '--silent', '--show-error', '--fail', '--noproxy', '*',
                        '--proto', '=https', '--connect-timeout', '4', '--max-time', '10',
                        '--resolve', host+':443:'+address, '--max-filesize', str(maximum),
                        '--output', str(output), '--write-out', '%{json}']
                if measure:
                    args += ['--range', '0-'+str(maximum-1)]
                args += ['https://'+host+path]
                result = inside(args, timeout=12, check=False)
                if result.returncode:
                    raise RuntimeError('measurement_curl_'+str(result.returncode))
                statistics = json.loads(result.stdout)
                if measure:
                    received = int(statistics['size_download'])
                    elapsed = float(statistics['time_total'])-float(statistics['time_starttransfer'])
                    if received < 1024*1024 or received > maximum or elapsed <= 0:
                        raise RuntimeError('measurement_too_short')
                    return {'bytes': received, 'elapsed_ms': round(elapsed*1000),
                            'estimated_mbps': round(received*8/elapsed/1e6, 2)}
                return output.read_bytes()
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            last = exc
        finally:
            output.unlink(missing_ok=True)
    raise RuntimeError('reference_unavailable') from last


def validate_yandex_probe(url):
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if (len(url) > 2048 or parsed.scheme != 'https' or not parsed.hostname or
        not parsed.hostname.endswith('.cdn.yandex.net') or parsed.username or parsed.password or
        parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError('untrusted_reference_url')
    return parsed.hostname, parsed.path+('?' + parsed.query if parsed.query else '')


def reference_sample(force=False):
    route = physical_route()
    fingerprint = hashlib.sha256(json.dumps({key: route.get(key) for key in ('dev', 'gateway', 'prefsrc')}, sort_keys=True).encode()).hexdigest()
    try:
        cached = json.loads((ROOT/'reference.json').read_text())
        if not force and cached.get('network') == fingerprint and cached.get('provider') == 'Yandex Internetometer':
            return cached
    except (OSError, ValueError):
        pass
    stage('reference', 'Запускаю замер прямого соединения: Яндекс Интернетометр.', 12)
    config = json.loads(provider_get('yandex.ru', '/internet/api/v0/get-probes?from=internet&nocache='+str(int(time.time()*1000)), 65536))
    probes = config.get('download', {}).get('probes', [])
    candidates = []
    for probe in probes:
        try:
            host, path = validate_yandex_probe(probe.get('url', ''))
        except (ValueError, TypeError):
            continue
        if '50mb' in path or '100mb' in path:
            candidates.append((host, path))
    if not candidates:
        raise RuntimeError('reference_schema_changed')
    host, path = candidates[0]
    # Short samples avoid a minute-long saturation while the user watches video.
    samples = [provider_get(host, path, 8*1024*1024, measure=True) for _ in range(2)]
    result = {'provider': 'Yandex Internetometer', 'network': fingerprint, 'time': int(time.time()),
              'estimated_mbps': max(x['estimated_mbps'] for x in samples), 'samples': samples,
              'short_sample': True, 'direct_physical_route': True}
    write(ROOT/'reference.json', json.dumps(result))
    return result



def tls_request(address, path, body=None, client=False, timeout=8):
    context = ssl.create_default_context(cadata=PINNED_CA)
    if client:
        context.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
    sock = socket.create_connection((address, 8443), timeout=timeout)
    try:
        tls = context.wrap_socket(sock, server_hostname=SERVER)
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
            cached.get('endpoint') in (SERVER, SERVER_LAN) and cached.get('physical_network') and
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
    for address in (SERVER, SERVER_LAN):
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
  vips = 0.0.0.0
  proposals = aes256gcm16-prfsha384-ecp384
  encap = yes
  fragmentation = yes
  mobike = yes
  dpd_delay = 15s
  local {{ auth = eap-tls; id = {identity}; eap_id = {identity}; certs = {ROOT}/client.pem }}
  remote {{ auth = pubkey; id = {SERVER}; cacerts = {ROOT}/ca.pem }}
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
  ip daddr {address} udp dport {{ 500, 4500 }} accept
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
        return tls_request(HEALTH, '/health', client=True).get('service') == 'evgenium-starfive'


def download(size=1048576):
    # A bounded integrity check, not a claim to have measured the ISP's maximum rate.
    block = hashlib.shake_256(b'evgenium-starfive-integrity-v1').digest(65536)
    expected = hashlib.sha256((block*(size//len(block)+1))[:size]).hexdigest()
    context = ssl.create_default_context(cadata=PINNED_CA)
    context.load_cert_chain(str(ROOT/'client.pem'), str(ROOT/'client-key.pem'))
    with namespace():
        sock = socket.create_connection((HEALTH, 8443), timeout=10)
        tls = context.wrap_socket(sock, server_hostname=SERVER)
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
        return
    if command(['systemctl', 'is-active', '--quiet', UNIT], check=False).returncode == 0:
        raise RuntimeError('Сначала отключите тестовый туннель перед сменой токена.')
    # A different account needs its own device credentials. Never reuse its certificate.
    for name in ('device', 'client-key.pem', 'client.pem', 'profile.json', 'request.pem',
                 'private/client-key.pem', 'x509/client.pem'):
        (ROOT/name).unlink(missing_ok=True)
    write(ROOT/'token', token)
    stage('off', 'Токен сохранён. Нажмите «Подключить».', 0, active=False, metrics={})


def connect(token='', repair=False):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if token:
        save_token(token)
    if not token_status()['has_token']:
        raise ValueError('Введите и подтвердите токен клиента.')
    # Do not auto-install packages or change the working VPN to make a test succeed.
    if not shutil.which('swanctl') or not Path('/usr/sbin/charon-systemd').is_file():
        raise RuntimeError('Для тестового туннеля нужен штатный пакет strongSwan.')
    if repair:
        write(ROOT/'recalibrate', '1')
    unit = f'''[Unit]
Description=Evgenium isolated StarFive Russia-to-Russia tunnel
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/sbin/vpnctl internal-starfive-tunnel
ExecStopPost=/usr/local/sbin/vpnctl internal-starfive-tunnel-cleanup
TimeoutStopSec=20
KillMode=mixed
UMask=0077
MemoryMax=256M
Restart=no
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
    stage('starting' , 'Готовлю тестовый туннель. Рабочий VPN сохранён.', 2, active=False, retry=0)
    command(['systemctl', 'restart' if repair else 'start', UNIT])
    print('Тестовый туннель запускается. Этапы видны в строке состояния.')


def disconnect():
    command(['systemctl', 'stop', UNIT], check=False, timeout=25)
    cleanup()
    stage('off', 'Тестовый туннель выключен. Рабочий VPN сохранён.', 0, active=False)
    print('Тестовый туннель выключен.')


def start_daemon(env):
    (RUNTIME/'charon.vici').unlink(missing_ok=True)
    log = (ROOT/'charon.log').open('w')
    daemon = subprocess.Popen(['ip', 'netns', 'exec', NS, '/usr/sbin/charon-systemd'],
                              env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    log.close()
    for _ in range(60):
        if STOP or daemon.poll() is not None:
            raise RuntimeError('daemon_stopped')
        if (RUNTIME/'charon.vici').exists() and swan('--stats', check=False, timeout=1).returncode == 0:
            break
        time.sleep(.1)
    swan('--load-creds', '--noprompt', '--file', ROOT/'connection.conf')
    swan('--load-conns', '--file', ROOT/'connection.conf')
    return daemon


def worker():
    global STOP
    STOP = False
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
    signal.signal(signal.SIGINT, lambda *_: globals().__setitem__('STOP', True))
    daemon = None
    try:
        cleanup()
        stage('prepare', 'Создаю отдельную сеть для испытаний.', 8, active=False)
        setup_network()
        try:
            reference = reference_sample(force=(ROOT/'recalibrate').exists())
        except (OSError, RuntimeError, ValueError):
            reference = {'available': False, 'provider': 'Yandex Internetometer'}
        (ROOT/'recalibrate').unlink(missing_ok=True)
        stage('token', 'Проверяю токен и сохранённое подключение этого устройства.', 20)
        identity, address = enroll()
        scope = 'lan' if address == SERVER_LAN else 'public-address'
        stage('daemon', 'Запускаю туннель IKEv2 Россия → Россия.', 40, scope=scope)
        daemon_configs(identity, address)
        env = {**os.environ, 'STRONGSWAN_CONF': str(ROOT/'strongswan.conf')}
        env.pop('NOTIFY_SOCKET', None)
        daemon = start_daemon(env)
        stage('handshake', 'Устанавливаю защищённое соединение со StarFive.', 60)
        swan('--initiate', '--child', 'starfive-net', timeout=35)
        if not installed():
            raise RuntimeError('sa_not_installed')
        stage('health', 'Проверяю туннель и защищённый ответ сервера.', 75)
        if not health():
            raise RuntimeError('health_failed')
        stage('measure', 'Проверяю передачу данных и целостность файла.', 85)
        metrics = download()
        metrics['reference'] = reference
        stage('connected', 'Туннель Россия → Россия работает. Рабочий VPN не переключался.', 100,
              active=True, metrics=metrics, since=int(time.time()))
        failures = 0
        while not STOP:
            for _ in range(100):
                if STOP:
                    break
                time.sleep(.1)
            if STOP:
                break
            try:
                ok = daemon.poll() is None and installed() and health()
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                ok = False
            failures = 0 if ok else failures+1
            if failures == 1:
                stage('checking', 'Ответ StarFive задерживается. Проверяю тестовое соединение.', 90, active=False)
                continue
            if failures >= 2:
                stage('repairing', 'Связь со StarFive потеряна. Восстанавливаю тестовый туннель.', 60, active=False)
                if daemon.poll() is not None:
                    inside(['ip', 'xfrm', 'state', 'flush'])
                    inside(['ip', 'xfrm', 'policy', 'flush'])
                    inside(['ip', 'route', 'flush', 'table', '51822'], check=False)
                    daemon = start_daemon(env)
                swan('--terminate', '--ike', 'starfive', check=False)
                swan('--initiate', '--child', 'starfive-net', timeout=35)
                if not installed() or not health():
                    raise RuntimeError('recovery_failed')
                failures = 0
            stage('connected', 'Туннель Россия → Россия работает. Рабочий VPN не переключался.', 100, active=True)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        code = str(exc) if re.fullmatch(r"[a-z_]{1,64}", str(exc)) else type(exc).__name__
        current = saved().get('phase', 'prepare')
        message = {'token': 'Не удалось подтвердить токен или получить сертификат StarFive.',
                   'handshake': 'StarFive не подтвердил подключение IKEv2.',
                   'measure': 'Проверка передачи данных не прошла.',
                   'repairing': 'Автовосстановление не удалось. Нажмите «Починить».'}.get(current, 'Тестовый туннель не запустился. Нажмите «Починить».')
        stage('failed', message+' Рабочий VPN сохранён.', 0, active=False, error_code=code, metrics={})
    finally:
        if daemon and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=6)
            except subprocess.TimeoutExpired:
                daemon.kill(); daemon.wait(timeout=3)
        cleanup()
        if STOP:
            stage('off', 'Тестовый туннель выключен. Рабочий VPN сохранён.', 0, active=False)
