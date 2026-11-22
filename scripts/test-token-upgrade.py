#!/usr/bin/env python3
"""Exercise the released 0.5.8 CLI and the candidate archive without touching host services.

Run as an ordinary Linux user with bubblewrap and native Python 3.12+:
    python3 scripts/test-token-upgrade.py [--repo REPOSITORY] [--case SCENARIO]
Each scenario gets separate mount, user, network and PID namespaces. systemctl,
nft, the other system programs, remote downloads and enrollment are fixtures.
Installation, command dispatch, embedded code, re-exec and rollback are real.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.parse import urlsplit

BASE_VERSION = '0.5.8'
BASE_SHA = 'f07621bfd0465886c6f5790cb845543b5a7439c47baf32159401a4b0cd14be4f'
CASES = ('idle', 'active', 'guarded', 'active-rollback', 'canonical-rollback',
         'admin-local', 'interrupted-upgrade', 'interrupted-rollback', 'damaged-download')
OLD_ROOT = Path('/etc/vpn-manager/starfive-tunnel')
NEW_ROOT = Path('/etc/vpn-manager/tunnel')
OLD_UNITS = ('evgenium-starfive-tunnel.service', 'evgenium-starfive-tunnel-recover.service',
             'evgenium-starfive-full-guard.service')
NEW_UNITS = ('evgenium-vpn.service', 'evgenium-vpn-recovery.service', 'evgenium-vpn-killswitch.service')
OLD_GUARD = 'evn_starfive_full'
RULES = f'table inet {OLD_GUARD} {{\n chain out {{ type filter hook output priority -42; policy drop; }}\n}}\n'
UNIT_DIR = Path('/etc/systemd/system')
WANTS = UNIT_DIR / 'multi-user.target.wants'
PREFIX = Path('/opt/vpn-manager')
CURRENT = PREFIX / 'current'
RELEASES = PREFIX / 'releases'
STATE = Path('/var/lib/vpn-manager')
FIXTURE = Path('/run/upgrade-fixture')
INPUTS = Path('/test-inputs')
CLI = '/usr/local/bin/vpn'
MANAGER = '/usr/local/sbin/vpnctl'
ADMIN = '/usr/local/sbin/vpn-manager-admin'
MANIFEST_URL = 'https://fixture.invalid/stable.json'
OLD_ARCHIVE = INPUTS / f'vpn-manager-{BASE_VERSION}.tar.gz'
POLICY = Path('/etc/vpn-manager/policy.json')
SETTINGS = Path('/etc/vpn-manager/settings.json')
SERVICES = FIXTURE / 'services.json'
TABLES = FIXTURE / 'nft-tables.json'
TRACE = FIXTURE / 'calls.jsonl'
CUT = FIXTURE / 'interrupt-after-state-rename'
IDENTITY = {
    'token': 'EVN1-' + 'A' * 43, 'device': 'fixture-linux-device',
    'client-key.pem': 'fixture private key\n', 'private/client-key.pem': 'fixture private key\n',
    'client.pem': 'fixture public certificate\n', 'profile.json': '{"preserve":true}',
    'ranking.json': '{}', 'selection.json': '{"route":"ee-tls"}',
    'device-info.json': '{"name":"fixture","number":12,"pending":false}',
}
MOCKS = ('systemctl', 'nft', 'ip', 'ss', 'conntrack', 'journalctl', 'resolvectl', 'swanctl', 'runuser', 'sudo')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def store(path, value):
    write(path, json.dumps(value))


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_version():
    return (INPUTS / 'VERSION').read_text().strip()


def assert_isolated():
    """All fixture writes and command doubles are allowed only after this check."""
    mapping = Path('/proc/self/uid_map').read_text().split()
    outer = int(os.environ['UPGRADE_TEST_OUTER_UID'])
    check(os.geteuid() == 0 and outer > 0 and list(map(int, mapping[:2])) == [0, outer],
          'a private UID mapping for the invoking non-root user is required')
    for scope in ('net', 'mnt', 'pid'):
        own = os.stat('/proc/self/ns/' + scope).st_ino
        check(own != int(os.environ['UPGRADE_TEST_OUTER_' + scope]), 'host ' + scope + ' namespace')
    check(not Path('/run/systemd/private').exists() and not Path('/run/dbus/system_bus_socket').exists(),
          'host services exposed in test')


def cmd(arguments, *, success=True):
    result = subprocess.run(list(map(str, arguments)), text=True, capture_output=True, timeout=90)
    if success and result.returncode:
        raise AssertionError(f'{arguments} returned {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result


def vpn(*args, success=True):
    return cmd([CLI, *args], success=success)


def systemctl(args):
    verbs = {'start', 'restart', 'stop', 'enable', 'disable', 'show', 'is-active', 'is-enabled',
             'daemon-reload', 'reset-failed'}
    verb = next((arg for arg in args if arg in verbs), None)
    check(verb, f'unsupported systemctl invocation {args}')
    if verb in ('daemon-reload', 'reset-failed'):
        return 0
    services = load(SERVICES)
    units = [arg for arg in args if arg.endswith('.service')]
    check(units, f'no unit in systemctl {args}')
    name = units[0]
    state = services.get(name, {})
    active = state.get('active', False)
    enabled = (WANTS / name).is_symlink()
    if verb in ('is-active', 'is-enabled'):
        yes = active if verb == 'is-active' else enabled
        if '--quiet' not in args:
            print(('active' if yes else 'inactive') if verb == 'is-active' else ('enabled' if yes else 'disabled'))
        return 0 if yes else (3 if verb == 'is-active' else 1)
    if verb == 'show':
        values = {'ActiveState': 'active' if active else 'inactive', 'SubState': 'running' if active else 'dead',
                  'MainPID': str(state.get('pid', 0)), 'FragmentPath': str(UNIT_DIR / name),
                  'UnitFileState': 'enabled' if enabled else 'disabled'}
        requested = [arg for arg in args if arg in values] or list(values)
        for key in requested:
            print(values[key] if '--value' in args or '-P' in args else f'{key}={values[key]}')
        return 0
    for name in units:
        unit = services.setdefault(name, {})
        link = WANTS / name
        if verb in ('stop', 'restart') or (verb == 'disable' and '--now' in args):
            pid = unit.pop('pid', 0)
            if pid:
                check(Path('/proc', str(pid), 'comm').read_text().strip() == 'sleep', 'unexpected fixture PID')
                os.kill(pid, 15)
            unit['active'] = False
        if verb in ('start', 'restart') or (verb == 'enable' and '--now' in args):
            unit['active'] = True
        if verb == 'enable' and not link.is_symlink():
            link.symlink_to('../' + name)
        if verb == 'disable':
            link.unlink(missing_ok=True)
    store(SERVICES, services)
    return 0


def system_double(name, args):
    assert_isolated()
    with TRACE.open('a') as trace:
        trace.write(json.dumps([name, *args]) + '\n')
    if name == 'sudo':
        check(args[:2] == ['-n', MANAGER] and len(args) >= 3, 'unexpected sudo wrapper invocation')
        os.execv(MANAGER, [MANAGER, *args[2:]])
    if name == 'systemctl':
        return systemctl(args)
    if name == 'ip' and '-j' in args:
        default = 'route' in args and 'main' in args and 'default' in args
        print(json.dumps([{'dev':'fixture0', 'gateway':'192.0.2.1', 'prefsrc':'192.0.2.2'}] if default else []))
    if name == 'nft':
        tables = load(TABLES)
        if 'list' in args and 'tables' in args:
            print(json.dumps({'nftables': [{'table': {'family': 'inet', 'name': t}} for t in tables]}))
        elif 'list' in args and 'table' in args:
            return int(args[-1] not in tables)
        elif 'delete' in args and 'table' in args:
            if args[-1] not in tables:
                return 1
            tables.remove(args[-1])
            store(TABLES, tables)
    return 0


def provide_download(url, limit=None):
    stable = load(INPUTS / 'stable.json')
    if url == MANIFEST_URL:
        data = (INPUTS / 'stable.json').read_bytes()
    elif url == stable['url']:
        data = b'intentionally corrupted fixture' if (FIXTURE / 'damage-download').exists() else (INPUTS / 'candidate.tar.gz').read_bytes()
    else:
        raise AssertionError(f'unexpected network request {url}')
    check(limit is None or len(data) <= limit, 'fixture exceeds download limit')
    return data


def enable_hooks():
    """Install fixtures at main entry in each real CLI process, also across execv."""
    def tracer(frame, event, _arg):
        api = frame.f_globals
        if event != 'call' or frame.f_code.co_name != 'main' or 'MANAGER_VERSION' not in api:
            return None
        sys.settrace(None)
        api['http_get'] = provide_download
        tunnel = api.get('vpn_tunnel') or api['starfive_tunnel']
        tunnel.ensure_dependencies = lambda: None
        tunnel.sync_device_name = lambda *args, **kwargs: tunnel.device_status()
        api['ensure_gui_dependencies'] = lambda: None
        if api['MANAGER_VERSION'] != BASE_VERSION and CUT.exists():
            rename = Path.rename
            def rename_and_interrupt(path, target):
                result = rename(path, target)
                if path == STATE / CUT.read_text():
                    CUT.unlink()
                    os._exit(85)
                return result
            Path.rename = rename_and_interrupt
        return None
    sys.settrace(tracer)


def prepare_tools():
    for directory in (FIXTURE, STATE, WANTS, Path('/fixture-home'), Path('/test-hooks'),
                      Path('/usr/local/bin'), Path('/usr/local/sbin')):
        directory.mkdir(parents=True, exist_ok=True)
    # /usr/bin is a private tmpfs. Even absolute service paths resolve to doubles.
    for name in ('python3', 'env', 'bash', 'sh', 'sleep'):
        (Path('/usr/bin') / name).symlink_to('/host-bin/' + name)
    for name in MOCKS:
        path = Path('/usr/bin') / name
        write(path, f'#!/usr/bin/python3 -B\nimport sys, runpy\nf = runpy.run_path("/review.py")["system_double"]\nsys.exit(f({name!r},sys.argv[1:]))\n', 0o755)
    write(Path('/test-hooks/sitecustomize.py'),
          "import os,runpy,sys\nif os.path.basename(sys.argv[0]) in ('vpnctl','vpnctl.py'):\n"
          " runpy.run_path('/review.py')['enable_hooks']()\n")
    write(Path('/etc/passwd'), 'root:x:0:0:root:/root:/bin/bash\nfixture:x:0:0:fixture:/fixture-home:/bin/bash\n', 0o644)
    write(Path('/etc/group'), 'root:x:0:\nfixture:x:0:\n', 0o644)
    store(SERVICES, {})
    store(TABLES, [])
    write(TRACE, '')


def install_reference(case, sleeper):
    settings = {'owner_user':'fixture', 'owner_home':'/fixture-home', 'xray_uid':0, 'xray_gid':0,
                'engine':'token-ipsec', 'manager_manifest_url':MANIFEST_URL, 'fixture_preserve':True}
    store(SETTINGS, settings)
    write(STATE / 'unified-migrated', '1')
    store(STATE / 'install-complete.json', {'version': BASE_VERSION})
    check(digest(OLD_ARCHIVE) == BASE_SHA, 'reference archive is not the published 0.5.8')
    dest = RELEASES / BASE_VERSION
    dest.mkdir(parents=True)
    with tarfile.open(OLD_ARCHIVE, 'r:gz') as package:
        files = package.getmembers()
        check(len(files) == 3 and {m.name for m in files} == {'VERSION', 'vpnctl.py', 'vpnadmin.py'}
              and all(m.isfile() for m in files), 'unexpected legacy archive')
        package.extractall(dest, filter='data')
    CURRENT.symlink_to(dest)
    Path(MANAGER).symlink_to(CURRENT / 'vpnctl.py')
    spec = importlib.util.spec_from_file_location('reference_manager', dest / 'vpnctl.py')
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    mod.sync_system_files()
    exclusions = mod.policy.defaults()
    exclusions.update(networks=['=fixture.invalid'], ports=['tcp:4321:out'], waydroid_direct=False)
    mod.policy.save(exclusions)
    write(FIXTURE / 'original-policy', POLICY.read_text())
    write(mod.XRAY, '#!/bin/sh\necho Xray ' + mod.SAFE_XRAY_VERSION + '\n', 0o755)
    OLD_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, value in IDENTITY.items():
        write(OLD_ROOT / name, value)
    # The published release writes its actual service templates into the fixture.
    tunnel = mod.starfive_tunnel
    tunnel.ensure_dependencies = lambda: None
    tunnel.connect()
    tunnel.persist_guard(RULES)
    live = case in ('active', 'active-rollback', 'damaged-download')
    guarded = live or case == 'guarded'
    if guarded:
        store(OLD_ROOT / 'full-network.json', {'active':live})
        if live:
            store(OLD_ROOT / 'network.json', {'measurement_ips':[]})
    else:
        (WANTS / OLD_UNITS[2]).unlink()
    store(TABLES, [OLD_GUARD] if guarded else [])
    store(SERVICES, {'evgenium-policy.service':{'active':live}, OLD_UNITS[0]:{'active':live, 'pid':sleeper.pid if live else 0}, OLD_UNITS[2]:{'active':guarded}})
    store(STATE / 'starfive-tunnel.json', {'phase':'connected' if live else 'off', 'active':live, 'heartbeat':time.monotonic()})
    write(OLD_ROOT / 'connection.conf', f'certificate={OLD_ROOT}/client.pem\n starfive {{\n   starfive-net {{\n')
    write(OLD_ROOT / 'strongswan.conf', 'socket=/run/evgenium-starfive-tunnel/charon.vici\n')
    write(TRACE, '')
    check(BASE_VERSION in vpn('version').stdout, 'public reference CLI did not start')


def assert_identity(root):
    check(root.is_dir() and stat.S_IMODE(root.stat().st_mode) == 0o700, f'missing/private directory {root}')
    for name, text in IDENTITY.items():
        path = root / name
        check(path.is_file() and path.read_text() == text and stat.S_IMODE(path.stat().st_mode) == 0o600,
              f'credential or private mode changed in {path}')
    check(POLICY.read_bytes() == (FIXTURE / 'original-policy').read_bytes(), 'user exclusions changed')
    check(load(SETTINGS)['fixture_preserve'], 'custom settings lost')


def assert_layout(root):
    canonical = root == NEW_ROOT
    absent_root, units, absent = (OLD_ROOT, NEW_UNITS, OLD_UNITS) if canonical else (NEW_ROOT, OLD_UNITS, NEW_UNITS)
    assert_identity(root)
    check(not absent_root.exists(), 'identity present in both layouts')
    for name, retired in zip(units, absent):
        path = UNIT_DIR / name
        check(path.is_file() and not os.path.lexists(UNIT_DIR / retired), f'units for role {name}')
        if canonical:
            check(stat.S_IMODE(path.stat().st_mode) == 0o644 and 'starfive' not in path.read_text().lower(), name)
    check((WANTS / units[1]).resolve(strict=True) == UNIT_DIR / units[1], 'lost enabled recovery unit')
    connection = (root / 'connection.conf').read_text()
    daemon = (root / 'strongswan.conf').read_text()
    rules = (root / 'full-guard.nft').read_text()
    check(str(root) in connection and str(absent_root) not in connection, 'generated certificate path')
    check(('/run/evgenium-starfive-tunnel/' in daemon) != canonical, 'generated daemon socket')
    check((OLD_GUARD in rules) != canonical, 'generated guard table')


def unchanged_dataplane():
    units = (*OLD_UNITS, *NEW_UNITS, 'evgenium-policy.service')
    for line in TRACE.read_text().splitlines():
        program, *args = json.loads(line)
        if program == 'systemctl' and any(v in args for v in ('start','stop','restart','disable')):
            check(not set(args).intersection(units), f'data plane modified: {args}')
        if program == 'ip':
            check(not set(args).intersection(('add','replace','delete','del','flush','set')), f'routes modified: {args}')
        if program == 'nft':
            check(not set(args).intersection(('delete','flush','-f')), f'firewall modified: {args}')
        check(not (program == 'conntrack' and '-D' in args), 'connection tracking flushed')
        check(not (program == 'resolvectl' and args and args[0] not in ('status','query')), 'resolver modified')


def assert_legacy_live(case, sleeper):
    live = case in ('active','active-rollback','damaged-download')
    assert_identity(OLD_ROOT)
    check(not NEW_ROOT.exists() and (WANTS / OLD_UNITS[2]).is_symlink(), 'protected old layout changed')
    check(OLD_GUARD in load(TABLES) and (OLD_ROOT / 'full-guard.nft').read_text() == RULES, 'old guard changed')
    state = json.loads(vpn('ui','state').stdout)
    check(state['tunnel']['has_token'] and state['guard'] and state['tunnel']['routes']['selected'] == 'ee-tls',
          'GUI backend lost token, guard or selected route')
    check(state['active'] == live, 'GUI backend reports wrong connection state')
    unchanged_dataplane()
    if live:
        check(load(SERVICES)[OLD_UNITS[0]] == {'active':True, 'pid':sleeper.pid} and sleeper.poll() is None,
              'running legacy worker was replaced')


def assert_old_release():
    check(CURRENT.resolve() == RELEASES / BASE_VERSION and BASE_VERSION in vpn('version').stdout,
          'old public CLI did not regain control')
    assert_layout(OLD_ROOT)


def public_rollback():
    vpn('manager-rollback')
    assert_old_release()


def mark_canonical_live(sleeper):
    vpn('on','--no-wait')
    services = load(SERVICES)
    check(services[NEW_UNITS[0]]['active'], 'controller did not start the canonical worker')
    services[NEW_UNITS[0]] = {'active':True, 'pid':sleeper.pid}
    services[NEW_UNITS[2]] = {'active':True}
    store(SERVICES, services)
    guard = re.search(r'table inet (\w+)', (NEW_ROOT / 'full-guard.nft').read_text())[1]
    store(TABLES, [guard])
    store(NEW_ROOT / 'full-network.json', {'active':True})
    (WANTS / NEW_UNITS[2]).symlink_to('../' + NEW_UNITS[2])
    write(TRACE, '')
    return guard


def canonical_downgrade(case, sleeper):
    guard = mark_canonical_live(sleeper)
    if case == 'admin-local':
        result = cmd([ADMIN, 'local', OLD_ARCHIVE], success=False)
        check(result.returncode != 0, f'unsafe local downgrade accepted\n{result.stdout}\n{result.stderr}')
    else:
        vpn('manager-rollback')
        check((STATE / 'rollback-on-disconnect').read_text() == str(RELEASES / BASE_VERSION), 'lost deferred rollback')
    check(CURRENT.resolve() == RELEASES / current_version(), 'downgrade replaced executable while tunnel was active')
    check(sleeper.poll() is None and load(SERVICES)[NEW_UNITS[0]]['pid'] == sleeper.pid and guard in load(TABLES),
          'downgrade interrupted canonical session')
    assert_identity(NEW_ROOT)
    unchanged_dataplane()
    vpn('off')
    if case == 'admin-local':
        cmd([ADMIN, 'local', OLD_ARCHIVE])
    assert_old_release()
    check(not (STATE / 'rollback-on-disconnect').exists(), 'stale deferred rollback')


def run_case(case, sleeper):
    install_reference(case, sleeper)
    if case == 'damaged-download':
        write(FIXTURE / 'damage-download','1')
        refused = vpn('update', success=False)
        check(refused.returncode and 'SHA' in refused.stderr + refused.stdout, 'damaged download accepted')
        check(CURRENT.resolve() == RELEASES / BASE_VERSION, 'damaged update replaced release')
        assert_legacy_live(case, sleeper)
        return
    if case == 'interrupted-upgrade':
        write(CUT, 'starfive-tunnel.json')
        result = vpn('update', success=False)
        check(result.returncode == 85 and (STATE / 'tunnel-layout-transition').read_text() == 'upgrade', 'forward interruption')
        check((STATE / 'tunnel.json').exists() and (OLD_ROOT / 'token').is_file() and not NEW_ROOT.exists(), 'wrong interrupted state')
    vpn('update')
    check(current_version() in vpn('version').stdout and (PREFIX / 'previous').resolve() == RELEASES / BASE_VERSION, 'upgrade pointers')
    if case in ('active','guarded','active-rollback'):
        assert_legacy_live(case, sleeper)
        vpn('update')
        assert_legacy_live(case, sleeper)
        if case == 'active-rollback':
            public_rollback()
            assert_legacy_live(case, sleeper)
        else:
            vpn('off')
            assert_layout(NEW_ROOT)
            check(OLD_GUARD not in load(TABLES), 'old protection survived explicit off')
            vpn('on','--no-wait')
            check(load(SERVICES)[NEW_UNITS[0]]['active'], 'subsequent on did not start named worker')
            assert_identity(NEW_ROOT)
            vpn('off')
            public_rollback()
        return
    assert_layout(NEW_ROOT)
    vpn('update')
    assert_layout(NEW_ROOT)
    if case in ('canonical-rollback','admin-local'):
        canonical_downgrade(case, sleeper)
    else:
        if case == 'interrupted-rollback':
            write(CUT, 'tunnel.json')
            result = vpn('manager-rollback', success=False)
            check(result.returncode == 85 and (STATE / 'tunnel-layout-transition').read_text() == 'rollback', 'rollback interruption')
            check(current_version() in vpn('version').stdout and NEW_ROOT.is_dir(), 'rollback switched before data')
        public_rollback()
    check(not (STATE / 'tunnel-layout-transition').exists(), 'unfinished migration marker')


def release_inputs(repo):
    version_file = repo / 'VERSION'
    version = version_file.read_text().strip()
    stable_file = repo / 'update/stable.json'
    stable = load(stable_file)
    check(stable['version'] == version != BASE_VERSION, f'expected stable manifest for VERSION {version}')
    name = Path(urlsplit(stable['url']).path).name
    check(name == f'vpn-manager-{version}.tar.gz', 'unexpected candidate archive name')
    candidate = repo / 'dist' / name
    old = repo / 'dist' / OLD_ARCHIVE.name
    check(digest(candidate) == stable['sha256'] and digest(old) == BASE_SHA, 'release archive checksum mismatch')
    return {version_file:'VERSION', stable_file:'stable.json', candidate:'candidate.tar.gz',
            old:OLD_ARCHIVE.name, Path(str(old) + '.sha256'):OLD_ARCHIVE.name + '.sha256'}


def sandbox_args(inputs):
    check(sys.platform.startswith('linux') and os.getuid() != 0, 'run natively as a non-root Linux user')
    bwrap = shutil.which('bwrap')
    check(bwrap, 'install bubblewrap with user namespace support')
    args = [bwrap,'--unshare-all','--die-with-parent','--new-session','--uid','0','--gid','0',
            '--ro-bind','/usr','/usr','--ro-bind','/usr/bin','/host-bin','--tmpfs','/usr/local',
            '--tmpfs','/usr/bin','--proc','/proc','--dev','/dev','--clearenv']
    for name in ('bin','sbin','lib','lib64'):
        path = Path('/') / name
        if path.is_symlink():
            args += ['--symlink',os.readlink(path),str(path)]
        elif path.is_dir():
            args += ['--ro-bind',str(path),str(path)]
    for name in ('etc','run','tmp','sys','opt','var','fixture-home','test-inputs','test-hooks'):
        args += ['--dir','/' + name]
    args += ['--ro-bind',str(Path(__file__).resolve()),'/review.py']
    for source, target in inputs.items():
        args += ['--ro-bind',str(source),str(INPUTS / target)]
    env = {'PATH':'/usr/bin', 'HOME':'/fixture-home', 'LANG':'C.UTF-8', 'PYTHONPATH':'/test-hooks',
           'PYTHONDONTWRITEBYTECODE':'1', 'UPGRADE_TEST_OUTER_UID':str(os.getuid())}
    for ns in ('net','pid','mnt'):
        env['UPGRADE_TEST_OUTER_' + ns] = str(os.stat('/proc/self/ns/' + ns).st_ino)
    for key, value in env.items():
        args += ['--setenv',key,value]
    return [*args,'--chdir','/tmp','/host-bin/python3','-B','/review.py','--inside']


def host_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent,
                        help='repository root, defaults to the parent of scripts/')
    parser.add_argument('--case', choices=CASES, help='run only this scenario')
    args = parser.parse_args()
    base = sandbox_args(release_inputs(args.repo.resolve(strict=True)))
    failures = []
    for case in (args.case,) if args.case else CASES:
        result = subprocess.run([*base,case])
        if result.returncode:
            failures.append(case)
    check(not failures, 'failed scenarios: ' + ', '.join(failures))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--inside':
        assert_isolated()
        prepare_tools()
        scenario = sys.argv[2]
        sleeper = subprocess.Popen(['/usr/bin/sleep','300'])
        try:
            run_case(scenario, sleeper)
            print(f'PASS {scenario} ({BASE_VERSION} -> {current_version()})', flush=True)
        finally:
            if sleeper.poll() is None:
                sleeper.terminate()
            sleeper.wait(timeout=5)
    else:
        host_main()
