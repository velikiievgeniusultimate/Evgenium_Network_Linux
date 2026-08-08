#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Evgenium Network Linux"
REPO="velikiievgeniusultimate/Evgenium_Network_Linux"
MANIFEST_URL="https://raw.githubusercontent.com/${REPO}/main/update/stable.json"
# Immutable clean-install implementation from the last fully tested installer.
BOOTSTRAP_COMMIT="67ff2b82fc36e476bfd91ca4ec0bb5ed999b11e0"
BOOTSTRAP_URL="https://raw.githubusercontent.com/${REPO}/${BOOTSTRAP_COMMIT}/install.sh"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -eq 0 ]]; then
    die "Запускай установщик обычным пользователем, без sudo. Он сам запросит sudo там, где нужно."
fi

OWNER_USER="$(id -un)"
command -v sudo >/dev/null 2>&1 || die "Не найден sudo."
command -v curl >/dev/null 2>&1 || die "Не найден curl."

# IMPORTANT: /etc/vpn-manager/settings.json is root:root 0600 by design.
# Never try to detect an existing install by reading it as the desktop user.
# These markers are root-owned/readable installation artifacts and are enough
# to distinguish a working modern install from a clean machine.
is_existing_install() {
    [[ -x /usr/local/sbin/vpnctl ]] || return 1
    [[ -f /opt/vpn-manager/current/VERSION ]] || return 1
    [[ -x /opt/vpn-manager/bin/xray ]] || return 1
    return 0
}

if is_existing_install; then
    say "Найдена существующая установка ${APP_NAME}."
    say "Переустановка не требуется. Подключаю stable-канал и проверяю обновления..."
    sudo -v

    # Settings are intentionally root-only, so update them as root.
    sudo python - "${MANIFEST_URL}" <<'PY'
import json, os, pathlib, sys, tempfile
manifest = sys.argv[1]
p = pathlib.Path('/etc/vpn-manager/settings.json')
if not p.exists():
    raise SystemExit('settings.json отсутствует; установка выглядит повреждённой')
d = json.loads(p.read_text())
if d.get('engine') != 'xray':
    raise SystemExit('установленный manager не является Xray edition')
d['manager_manifest_url'] = manifest
fd, tmp = tempfile.mkstemp(prefix='settings.', suffix='.json', dir=str(p.parent))
try:
    with os.fdopen(fd, 'w') as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
finally:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY

    # Repair the admin entrypoint if an earlier/manual installation missed it.
    if [[ -x /opt/vpn-manager/current/vpnadmin.py ]]; then
        sudo ln -sfn /opt/vpn-manager/current/vpnadmin.py /usr/local/sbin/vpn-manager-admin
    fi

    sudo /usr/local/sbin/vpnctl internal-sync

    printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/vpnctl\n' "$OWNER_USER" | \
        sudo tee /etc/sudoers.d/vpn-manager >/dev/null
    sudo chmod 0440 /etc/sudoers.d/vpn-manager
    if command -v visudo >/dev/null 2>&1; then
        sudo visudo -cf /etc/sudoers.d/vpn-manager >/dev/null || {
            sudo rm -f /etc/sudoers.d/vpn-manager
            die "Проверка sudoers не прошла."
        }
    fi

    sudo /usr/local/sbin/vpnctl update
    ok "${APP_NAME} уже установлен. Ничего заново не переустанавливалось."
    echo
    echo "Дальше достаточно: vpn update"
    exit 0
fi

say "Существующая установка не найдена. Запускаю чистую установку..."
# Delegate clean install to an immutable, already-tested bootstrap implementation.
# On a genuinely clean machine its old existing-install detector is irrelevant.
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "${BOOTSTRAP_URL}" | bash
