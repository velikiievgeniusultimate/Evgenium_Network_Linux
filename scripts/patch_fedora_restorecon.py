from pathlib import Path
p=Path('install.sh')
s=p.read_text()
old='sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager /usr/local/sbin /usr/local/bin >/dev/null 2>&1 || true'
if s.count(old) != 2:
    raise SystemExit(f'expected 2 broad restorecon calls, got {s.count(old)}')
s=s.replace(old, 'sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager >/dev/null 2>&1 || true', 1)
new='''sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager >/dev/null 2>&1 || true
    for path in /usr/local/sbin/vpnctl /usr/local/sbin/vpn-manager-admin /usr/local/bin/vpn /usr/local/bin/evgenium-network; do
        if [[ -e "$path" || -L "$path" ]]; then
            sudo restorecon -F "$path" >/dev/null 2>&1 || true
        fi
    done'''
s=s.replace(old, new, 1)
p.write_text(s)
