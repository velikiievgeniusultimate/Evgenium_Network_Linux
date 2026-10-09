import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('vpn_dns_real', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec); spec.loader.exec_module(vpn)

class DnsFailoverTests(unittest.TestCase):
    def test_dead_first_resolver_does_not_block_udp_or_tcp_clients(self):
        binary = Path(os.environ.get('XRAY_TEST_BINARY', '/opt/vpn-manager/bin/xray'))
        if not binary.exists(): self.skipTest('Pinned Xray not installed')
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(('127.0.0.1', 0)); upstream.settimeout(.1)
        upstream_port = upstream.getsockname()[1]
        stopped = threading.Event()
        def serve():
            while not stopped.is_set():
                try: data, peer = upstream.recvfrom(4096)
                except socket.timeout: continue
                except OSError: return
                end = 12
                while data[end]: end += data[end] + 1
                end += 5
                qtype = struct.unpack('!H', data[end-4:end-2])[0]
                ip = b'\x7f\0\0\x2a' if qtype == 1 else b'\0'*15+b'\x2a'
                answer = b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,60,len(ip))+ip
                upstream.sendto(data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:end]+answer, peer)
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        reserve = socket.socket(); reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
        dns = vpn.dns_config()
        dns['servers'] = [{'address':'127.0.0.2','port':upstream_port,'timeoutMs':250}, {'address':'127.0.0.1','port':upstream_port,'timeoutMs':250}]
        cfg = {'log':{'loglevel':'none'},'dns':dns,'inbounds':[{'tag':'dns-in-v4','listen':'127.0.0.1','port':port,'protocol':'dokodemo-door','settings':{'address':vpn.DNS_PRIMARY_IP,'port':53,'network':'tcp,udp'}}], 'outbounds':[{'tag':'proxy','protocol':'freedom'},vpn.dns_outbound()], 'routing':{'rules':vpn.dns_routing_rules()}}
        try:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/'config.json'; p.write_text(json.dumps(cfg))
                subprocess.run([str(binary),'run','-test','-config',str(p)],check=True,capture_output=True)
                proc=subprocess.Popen([str(binary),'run','-config',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    deadline=time.monotonic()+3
                    while True:
                        try:
                            with socket.create_connection(('127.0.0.1',port),timeout=.1): break
                        except OSError:
                            if time.monotonic()>deadline: self.fail('DNS listener did not start')
                            time.sleep(.02)
                    for transport in ('udp','tcp'):
                        good, detail = vpn._dns_listener_check(port,transport)
                        self.assertTrue(good, (transport, detail))
                finally:
                    proc.terminate();proc.wait(timeout=3)
        finally:
            stopped.set(); upstream.close(); thread.join(timeout=1)
