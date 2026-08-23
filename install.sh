#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Evgenium Network Linux"
REPO="velikiievgeniusultimate/Evgenium_Network_Linux"
MANIFEST_URL="https://raw.githubusercontent.com/${REPO}/main/update/stable.json"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -eq 0 ]]; then
    die "Запускай установщик обычным пользователем, без sudo. Он сам запросит sudo там, где нужно."
fi

OWNER_USER="$(id -un)"
OWNER_HOME="${HOME}"
VPN_HOME="${OWNER_HOME}/Vpn"
CONFIG_DIR="${VPN_HOME}/VPN configs"
DIRECT_SITES="${VPN_HOME}/DIRECT sites.txt"
DIRECT_NETWORKS="${VPN_HOME}/DIRECT networks.txt"

command -v sudo >/dev/null 2>&1 || die "Не найден sudo."
command -v curl >/dev/null 2>&1 || die "Не найден curl. Он нужен, чтобы получить установщик и stable manifest."

DISTRO=""
if [[ -f /etc/arch-release ]]; then
    DISTRO="arch"
elif [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" == "fedora" ]]; then
        DISTRO="fedora"
    fi
fi
[[ -n "$DISTRO" ]] || die "Автоустановщик поддерживает Arch Linux и Fedora Linux."

find_python() {
    if command -v python3 >/dev/null 2>&1; then
        command -v python3
    elif command -v python >/dev/null 2>&1; then
        command -v python
    else
        return 1
    fi
}

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
    PYTHON_BIN="$(find_python || true)"
    [[ -n "$PYTHON_BIN" ]] || die "Не найден Python 3, хотя VPN Manager уже установлен."

    sudo "$PYTHON_BIN" - "${MANIFEST_URL}" <<'PY'
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

say "Обнаружена система: ${DISTRO}. Получаю sudo для чистой установки..."
sudo -v

say "Проверяю зависимости..."
if [[ "$DISTRO" == "arch" ]]; then
    command -v pacman >/dev/null 2>&1 || die "Arch обнаружен, но pacman не найден."
    packages=(python curl nftables iproute2 ca-certificates qt6-declarative)
    missing=()
    for p in "${packages[@]}"; do
        pacman -Q "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if ((${#missing[@]})); then
        say "Устанавливаю официальные Arch-пакеты: ${missing[*]}"
        sudo pacman -S --needed --noconfirm "${missing[@]}"
    else
        ok "Зависимости Arch уже установлены."
    fi
else
    command -v dnf >/dev/null 2>&1 || die "Fedora обнаружена, но dnf не найден."
    command -v rpm >/dev/null 2>&1 || die "Fedora обнаружена, но rpm не найден."
    # qt6-qtdeclarative-devel contains Fedora's Qt 6 QML runner
    # (/usr/bin/qml-qt6 -> /usr/lib64/qt6/bin/qml).
    packages=(python3 curl nftables iproute ca-certificates shadow-utils qt6-qtdeclarative-devel)
    missing=()
    for p in "${packages[@]}"; do
        rpm -q "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if ((${#missing[@]})); then
        say "Устанавливаю официальные Fedora-пакеты: ${missing[*]}"
        sudo dnf install -y --setopt=install_weak_deps=False "${missing[@]}"
    else
        ok "Зависимости Fedora уже установлены."
    fi
fi

PYTHON_BIN="$(find_python || true)"
[[ -n "$PYTHON_BIN" ]] || die "После установки зависимостей не найден Python 3."
for c in curl nft ip; do
    command -v "$c" >/dev/null 2>&1 || die "После установки не найдена команда '$c'."
done

QML_RUNTIME=""
for candidate in /usr/bin/qml6 /usr/bin/qml-qt6 /usr/lib/qt6/bin/qml /usr/lib64/qt6/bin/qml /usr/bin/qml; do
    if [[ -x "$candidate" ]]; then
        QML_RUNTIME="$candidate"
        break
    fi
done
[[ -n "$QML_RUNTIME" ]] || warn "Qt 6 QML runner пока не найден; VPN CLI установится, но GUI не запустится до установки Qt QML runtime."

mkdir -p "${CONFIG_DIR}"
chmod 700 "${VPN_HOME}" "${CONFIG_DIR}"
touch "${DIRECT_SITES}" "${DIRECT_NETWORKS}"
chmod 600 "${DIRECT_SITES}" "${DIRECT_NETWORKS}"

NOLOGIN="$(command -v nologin || true)"
if [[ -z "$NOLOGIN" ]]; then
    for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do
        if [[ -x "$candidate" ]]; then
            NOLOGIN="$candidate"
            break
        fi
    done
fi
[[ -n "$NOLOGIN" ]] || die "Не найден nologin для системного пользователя vpn-xray."

say "Создаю изолированного системного пользователя vpn-xray..."
if ! getent passwd vpn-xray >/dev/null; then
    sudo useradd --system --home-dir /var/lib/vpn-manager/xray --shell "$NOLOGIN" vpn-xray
fi
XRAY_UID="$(id -u vpn-xray)"
XRAY_GID="$(id -g vpn-xray)"

sudo install -d -m 0755 /opt/vpn-manager /opt/vpn-manager/bin /opt/vpn-manager/releases
sudo install -d -m 0755 /etc/vpn-manager /usr/local/sbin /usr/local/bin
sudo install -d -o vpn-xray -g vpn-xray -m 0750 /var/lib/vpn-manager /var/lib/vpn-manager/xray

# On SELinux-enabled Fedora, restore the distribution-defined labels for the
# application directories. Arch simply skips this because restorecon is absent.
if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager /usr/local/sbin /usr/local/bin >/dev/null 2>&1 || true
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Получаю stable manifest из GitHub..."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "${MANIFEST_URL}" -o "${tmp}/stable.json"

readarray -t manifest < <("$PYTHON_BIN" - "${tmp}/stable.json" "${REPO}" <<'PY'
import json, re, sys, urllib.parse
p, repo = sys.argv[1:]
m = json.load(open(p))
if m.get("schema") != 1 or m.get("channel") != "stable":
    raise SystemExit("bad stable manifest")
version = str(m.get("version", ""))
sha = str(m.get("sha256", "")).lower()
url = str(m.get("url", ""))
if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
    raise SystemExit("bad version")
if not re.fullmatch(r"[0-9a-f]{64}", sha):
    raise SystemExit("bad sha256")
u = urllib.parse.urlsplit(url)
if u.scheme != "https" or u.hostname != "raw.githubusercontent.com":
    raise SystemExit("release URL must use raw.githubusercontent.com over HTTPS")
expected_prefix = "/" + repo + "/main/dist/"
if not u.path.startswith(expected_prefix):
    raise SystemExit("release URL points outside the expected repository")
print(version)
print(sha)
print(url)
PY
)

VERSION="${manifest[0]:-}"
EXPECTED_SHA="${manifest[1]:-}"
RELEASE_URL="${manifest[2]:-}"
[[ -n "$VERSION" && -n "$EXPECTED_SHA" && -n "$RELEASE_URL" ]] || die "Не удалось разобрать stable manifest."

say "Скачиваю VPN Manager ${VERSION}..."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "${RELEASE_URL}" -o "${tmp}/release.tar.gz"

GOT_SHA="$(sha256sum "${tmp}/release.tar.gz" | awk '{print $1}')"
[[ "$GOT_SHA" == "$EXPECTED_SHA" ]] || die "SHA-256 релиза не совпал. Установка остановлена."
ok "SHA-256 релиза подтверждён."

mkdir "${tmp}/release"
"$PYTHON_BIN" - "${tmp}/release.tar.gz" "${tmp}/release" "$VERSION" <<'PY'
import pathlib, sys, tarfile
archive, out, expected_version = map(pathlib.Path, sys.argv[1:])
allowed = {"vpnctl.py", "vpnadmin.py", "VERSION"}
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    names = {m.name for m in members}
    if names != allowed:
        raise SystemExit(f"unexpected archive members: {sorted(names)}")
    for m in members:
        p = pathlib.PurePosixPath(m.name)
        if not m.isfile() or p.is_absolute() or ".." in p.parts:
            raise SystemExit("unsafe archive member")
    tf.extractall(out)
version = (out / "VERSION").read_text().strip()
if version != str(expected_version):
    raise SystemExit(f"VERSION mismatch: {version} != {expected_version}")
PY
chmod 755 "${tmp}/release/vpnctl.py" "${tmp}/release/vpnadmin.py"
"$PYTHON_BIN" -m py_compile "${tmp}/release/vpnctl.py" "${tmp}/release/vpnadmin.py"
"$PYTHON_BIN" "${tmp}/release/vpnctl.py" --self-test >/dev/null
ok "Compile + self-test прошли."

release_dir="/opt/vpn-manager/releases/${VERSION}"
sudo rm -rf "${release_dir}"
sudo install -d -m 0755 "${release_dir}"
sudo install -m 0755 "${tmp}/release/vpnctl.py" "${release_dir}/vpnctl.py"
sudo install -m 0755 "${tmp}/release/vpnadmin.py" "${release_dir}/vpnadmin.py"
sudo install -m 0644 "${tmp}/release/VERSION" "${release_dir}/VERSION"
sudo ln -sfn "${release_dir}" /opt/vpn-manager/current
sudo ln -sfn /opt/vpn-manager/current/vpnctl.py /usr/local/sbin/vpnctl
sudo ln -sfn /opt/vpn-manager/current/vpnadmin.py /usr/local/sbin/vpn-manager-admin

"$PYTHON_BIN" - "$OWNER_USER" "$OWNER_HOME" "$CONFIG_DIR" "$DIRECT_SITES" "$DIRECT_NETWORKS" "$XRAY_UID" "$XRAY_GID" "$MANIFEST_URL" > "${tmp}/settings.json" <<'PY'
import json, sys
user, home, configs, sites, networks, uid, gid, manifest = sys.argv[1:]
print(json.dumps({
    "schema": 2,
    "engine": "xray",
    "owner_user": user,
    "owner_home": home,
    "config_dir": configs,
    "direct_sites": sites,
    "direct_networks": networks,
    "xray_uid": int(uid),
    "xray_gid": int(gid),
    "manager_manifest_url": manifest,
}, ensure_ascii=False, indent=2))
PY
sudo install -m 0600 "${tmp}/settings.json" /etc/vpn-manager/settings.json

printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/vpnctl\n' "$OWNER_USER" > "${tmp}/sudoers"
sudo install -o root -g root -m 0440 "${tmp}/sudoers" /etc/sudoers.d/vpn-manager
if command -v visudo >/dev/null 2>&1; then
    sudo visudo -cf /etc/sudoers.d/vpn-manager >/dev/null || {
        sudo rm -f /etc/sudoers.d/vpn-manager
        die "Проверка sudoers не прошла."
    }
else
    warn "visudo не найден; sudoers установлен без отдельной syntax-check."
fi

say "Устанавливаю systemd unit, GUI и команду vpn..."
sudo /usr/local/sbin/vpnctl internal-sync
sudo systemctl disable vpn-xray.service >/dev/null 2>&1 || true

if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager /usr/local/sbin /usr/local/bin >/dev/null 2>&1 || true
fi

say "Устанавливаю совместимый Xray-core..."
sudo /usr/local/sbin/vpnctl core-update

ok "${APP_NAME} установлен на ${DISTRO}."
echo
echo "Команда: vpn"
echo "Приложение KDE: Evgenium Network"
echo "Конфиги: ${CONFIG_DIR}"
echo
echo "Начать:"
echo "  vpn list"
echo "  vpn on"
echo
echo "Обновление в будущем:"
echo "  vpn update"
