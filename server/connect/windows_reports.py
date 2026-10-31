"""Bounded Windows diagnostics: numerical probes only, no logs or packet contents."""
import math
import re

ROUTES = {'ru-wg', 'ru-tcp', 'ru-xhttp'}
SERVICES = {'dns_https', 'discord_api', 'discord_cdn', 'vk', 'github'}


def number(value, maximum=10**18, integer=True):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError('metric')
    if integer and int(value) != value:
        raise ValueError('integer')
    return int(value) if integer else round(value, 4)


def only(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError('fields')
    return value


def clean_windows(body):
    only(body, ('schema', 'event', 'system', 'manager', 'report_id', 'time', 'os_build', 'checks', 'counters', 'adapters'))
    if body.get('schema') != 1 or body.get('event') != 'support_bundle' or body.get('system') != 'windows':
        raise ValueError('schema')
    if not re.fullmatch(r'[a-f0-9]{32}', str(body.get('report_id', ''))) or not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}', str(body.get('manager', ''))):
        raise ValueError('identity')
    result = dict(schema=1, event='support_bundle', system='windows', manager=body['manager'], report_id=body['report_id'], time=number(body['time'], 4102444800), os_build=number(body['os_build'], 999999))
    counters = only(body['counters'], ('tcp_sent', 'tcp_received', 'tcp_retransmitted'))
    result['counters'] = {k: number(v) for k, v in counters.items()}
    adapters = body['adapters']
    if not isinstance(adapters, list) or len(adapters) > 64:
        raise ValueError('adapters')
    result['adapters'] = []
    for item in adapters:
        only(item, ('received_bytes', 'sent_bytes', 'received_errors', 'sent_errors', 'received_discards', 'sent_discards'))
        result['adapters'].append({k: number(v) for k, v in item.items()})
    checks = only(body['checks'], ('routes', 'transfers', 'packets', 'services'))
    clean = dict(routes=[], transfers=[], packets={}, services=[])
    for key, maximum in (('routes', 3), ('transfers', 3), ('services', 5)):
        if not isinstance(checks.get(key), list) or len(checks[key]) > maximum:
            raise ValueError('probe_count')
    for route in checks['routes']:
        only(route, ('id', 'label', 'download_mbps', 'rtt_ms', 'losses', 'good', 'error'))
        if route.get('id') not in ROUTES or type(route.get('good')) is not bool:
            raise ValueError('route')
        clean['routes'].append(dict(id=route['id'], good=route['good'], download_mbps=number(route['download_mbps'], 100000, False), rtt_ms=number(route['rtt_ms'], 120000), losses=number(route['losses'], 100000)))
    for transfer in checks['transfers']:
        only(transfer, ('route', 'direction', 'bytes', 'elapsed_ms', 'mbps', 'ok'))
        if transfer.get('route') not in ROUTES or transfer.get('direction') != 'upload' or type(transfer.get('ok')) is not bool:
            raise ValueError('transfer')
        clean['transfers'].append(dict(route=transfer['route'], direction='upload', bytes=number(transfer['bytes'], 4*1024*1024), elapsed_ms=number(transfer['elapsed_ms'], 120000), mbps=number(transfer['mbps'], 100000, False), ok=transfer['ok']))
    packets = only(checks.get('packets'), ROUTES)
    for route, probes in packets.items():
        if not isinstance(probes, list) or len(probes) > 6:
            raise ValueError('packets')
        clean['packets'][route] = []
        for probe in probes:
            only(probe, ('size', 'sent', 'received', 'rtt_us', 'elapsed_ms', 'error'))
            if probe.get('size') not in (0, 64, 256, 512, 1024, 1200, 1400) or probe.get('error', '') not in ('', 'udp_associate_unavailable', 'send_error', 'no_udp_response'):
                raise ValueError('packet_probe')
            row = {k: number(probe[k], cap) for k, cap in [('size', 1400), ('sent', 100), ('received', 100), ('rtt_us', 120000000), ('elapsed_ms', 120000)]}
            if row['received'] > row['sent']:
                raise ValueError('packet_count')
            row['error'] = probe.get('error', '')
            clean['packets'][route].append(row)
    for probe in checks['services']:
        only(probe, ('service', 'ok', 'http_status', 'elapsed_ms'))
        if probe.get('service') not in SERVICES or type(probe.get('ok')) is not bool:
            raise ValueError('service')
        clean['services'].append(dict(service=probe['service'], ok=probe['ok'], http_status=number(probe['http_status'], 599), elapsed_ms=number(probe['elapsed_ms'], 120000)))
    result['checks'] = clean
    return result
