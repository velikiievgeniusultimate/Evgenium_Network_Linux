"""Bounded Windows diagnostics: numerical probes only, no logs or packet contents."""
import math
import re

ROUTES = {'ru-wg', 'ru-tcp', 'ru-xhttp'}
SERVICES = {'dns_https', 'discord_api', 'discord_cdn', 'vk', 'github', 'telegram_web', 'adobe'}
FOLDER_PROBES = {'temp', 'desktop', 'documents', 'downloads', 'telegram_files', 'shell_desktop', 'shell_downloads'}
FOLDER_KINDS = {'local', 'cloud', 'network', 'reparse', 'unknown'}
FOLDER_STATUSES = {'ok', 'missing', 'read_only', 'unavailable', 'denied', 'busy', 'network', 'disk_full', 'long_path',
                   'redirected', 'error'}
FOLDER_STEPS = {'lookup', 'mkdir', 'write', 'rename', 'read', 'delete', 'done', 'shell'}
BOOL_FIELDS = {
    'applications': {'photoshop_installed', 'photoshop_running', 'photoshop_profile', 'telegram_installed',
                     'telegram_running', 'onedrive_configured', 'onedrive_running'},
    'storage': {'elevated'},
    'settings': {'smb_running', 'proxy', 'proxy_pac'},
    'events': {'application_log_available', 'defender_log_available'},
}
NUMBER_FIELDS = {
    'applications': {},
    'storage': {'fixed_disks': 256, 'low_space_disks': 256, 'temp_free_mb': 4000000},
    'settings': {'mapped_disks': 64, 'smb_checked': 4, 'smb_reachable': 4, 'lan_subnets': 256, 'defender_cfa': 4},
    'events': {'photoshop_events': 150, 'telegram_events': 150, 'explorer_events': 150, 'onedrive_events': 150,
               'cfa_blocked': 100, 'cfa_audited': 100},
}


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


def boolean(value):
    if type(value) is not bool:
        raise ValueError('boolean')
    return value


def choice(value, options):
    if not isinstance(value, str) or value not in options:
        raise ValueError('value')
    return value


def clean_local(checks):
    cleaned = {}
    for key, check in only(checks, FOLDER_PROBES | BOOL_FIELDS.keys()).items():
        if isinstance(check, dict) and set(check) == {'status', 'elapsed_ms'}:
            cleaned[key] = dict(status=choice(check['status'], {'timeout', 'error'}),
                                elapsed_ms=number(check['elapsed_ms'], 120000))
        elif key in FOLDER_PROBES:
            only(check, ('kind', 'status', 'step', 'elapsed_ms', 'read_only', 'cleanup_ok'))
            cleaned[key] = dict(kind=choice(check['kind'], FOLDER_KINDS),
                                status=choice(check['status'], FOLDER_STATUSES),
                                step=choice(check['step'], FOLDER_STEPS),
                                elapsed_ms=number(check['elapsed_ms'], 120000),
                                read_only=boolean(check['read_only']), cleanup_ok=boolean(check['cleanup_ok']))
        else:
            booleans, numbers = BOOL_FIELDS[key], NUMBER_FIELDS[key]
            only(check, booleans | numbers.keys())
            fields = {name: boolean(check[name]) for name in booleans}
            for name, maximum in numbers.items():
                value = check[name]
                # -1 is an unavailable Defender setting.
                fields[name] = -1 if name == 'defender_cfa' and type(value) is int and value == -1 else number(value, maximum)
            cleaned[key] = fields
    return cleaned


def clean_windows(body):
    fields = {'schema', 'event', 'system', 'manager', 'report_id', 'time', 'os_build', 'checks', 'counters', 'adapters'}
    schema = body.get('schema') if isinstance(body, dict) else None
    only(body, fields | ({'local', 'network_status'} if schema == 2 else set()))
    if type(schema) is not int or schema not in (1, 2) or body.get('event') != 'support_bundle' or body.get('system') != 'windows':
        raise ValueError('schema')
    if not re.fullmatch(r'[a-f0-9]{32}', str(body.get('report_id', ''))) or not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}', str(body.get('manager', ''))):
        raise ValueError('identity')
    result = dict(schema=schema, event='support_bundle', system='windows', manager=body['manager'], report_id=body['report_id'], time=number(body['time'], 4102444800), os_build=number(body['os_build'], 999999))
    if schema == 2:
        result['local'] = clean_local(body['local'])
        result['network_status'] = choice(body['network_status'], {'ok', 'connect_failed', 'timeout', 'error'})
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
    for key, maximum in (('routes', 3), ('transfers', 3), ('services', 7)):
        if not isinstance(checks.get(key), list) or len(checks[key]) > maximum:
            raise ValueError('probe_count')
    for route in checks['routes']:
        only(route, ('id', 'label', 'download_mbps', 'rtt_ms', 'losses', 'good', 'error'))
        if route.get('id') not in ROUTES or type(route.get('good')) is not bool:
            raise ValueError('route')
        clean['routes'].append(dict(id=route['id'], good=route['good'], download_mbps=number(route['download_mbps'], 100000, False), rtt_ms=number(route['rtt_ms'], 120000), losses=number(route.get('losses', 0), 100000)))
    for transfer in checks['transfers']:
        only(transfer, ('route', 'direction', 'bytes', 'elapsed_ms', 'mbps', 'ok', 'error', 'http_status'))
        if transfer.get('route') not in ROUTES or transfer.get('direction') != 'upload' or type(transfer.get('ok')) is not bool:
            raise ValueError('transfer')
        metrics = dict(route=transfer['route'], direction='upload', bytes=number(transfer['bytes'], 4*1024*1024),
                       elapsed_ms=number(transfer['elapsed_ms'], 120000), mbps=number(transfer['mbps'], 100000, False), ok=transfer['ok'])
        if 'error' in transfer:
            metrics['error'] = choice(transfer['error'], {'', 'timeout', 'network', 'http'})
        if 'http_status' in transfer:
            metrics['http_status'] = number(transfer['http_status'], 599)
        clean['transfers'].append(metrics)
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
