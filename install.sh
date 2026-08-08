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

# Existing modern installation: do not rebuild system layout, just attach the
# stable channel and use the manager's own transactional updater.
if [[ -x /usr/local/sbin/vpn-manager-admin && -x /usr/local/sbin/vpnctl && -x /usr/local/bin/vpn ]]; then
    if [[ -f /etc/vpn-manager/settings.json ]] && grep -q '"engine"[[:space:]]*:[[:space:]]*"xray"' /etc/vpn-manager/settings.json 2>/dev/null; then
        say "Найдена существующая Xray-установка. Подключаю stable-канал GitHub..."
        sudo /usr/local/sbin/vpn-manager-admin source "${MANIFEST_URL}"
        /usr/local/bin/vpn update
        ok "${APP_NAME} уже установлен и подключён к GitHub updates."
        echo
        echo "Дальше достаточно: vpn update"
        exit 0
    fi
fi

[[ -f /etc/arch-release ]] || die "Автоустановщик сейчас поддерживает Arch Linux."

say "Получаю sudo для системной установки..."
sudo -v

say "Проверяю зависимости..."
missing=()
for p in python curl nftables iproute2 ca-certificates; do
    pacman -Q "$p" >/dev/null 2>&1 || missing+=("$p")
done
if ((${#missing[@]})); then
    say "Устанавливаю официальные Arch-пакеты: ${missing[*]}"
    sudo pacman -S --needed --noconfirm "${missing[@]}"
else
    ok "Зависимости уже установлены."
fi

for c in python curl nft ip; do
    command -v "$c" >/dev/null 2>&1 || die "После установки не найдена команда '$c'."
done

mkdir -p "${CONFIG_DIR}"
chmod 700 "${VPN_HOME}" "${CONFIG_DIR}"
touch "${DIRECT_SITES}" "${DIRECT_NETWORKS}"
chmod 600 "${DIRECT_SITES}" "${DIRECT_NETWORKS}"

say "Создаю изолированного системного пользователя vpn-xray..."
if ! getent passwd vpn-xray >/dev/null; then
    sudo useradd --system --home-dir /var/lib/vpn-manager/xray --shell /usr/bin/nologin vpn-xray
fi
XRAY_UID="$(id -u vpn-xray)"
XRAY_GID="$(id -g vpn-xray)"

sudo install -d -m 0755 /opt/vpn-manager /opt/vpn-manager/bin /opt/vpn-manager/releases
sudo install -d -m 0755 /etc/vpn-manager /usr/local/sbin /usr/local/bin
sudo install -d -o vpn-xray -g vpn-xray -m 0750 /var/lib/vpn-manager /var/lib/vpn-manager/xray

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Получаю stable manifest из GitHub..."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "${MANIFEST_URL}" -o "${tmp}/stable.json"

readarray -t manifest < <(python - "${tmp}/stable.json" "${REPO}" <<'PY'
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
python - "${tmp}/release.tar.gz" "${tmp}/release" "$VERSION" <<'PY'
import pathlib, re, sys, tarfile
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
python -m py_compile "${tmp}/release/vpnctl.py" "${tmp}/release/vpnadmin.py"
python "${tmp}/release/vpnctl.py" --self-test >/dev/null
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

python - "$OWNER_USER" "$OWNER_HOME" "$CONFIG_DIR" "$DIRECT_SITES" "$DIRECT_NETWORKS" "$XRAY_UID" "$XRAY_GID" "$MANIFEST_URL" > "${tmp}/settings.json" <<'PY'
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

say "Устанавливаю systemd unit и команду vpn..."
sudo /usr/local/sbin/vpnctl internal-sync
sudo systemctl disable vpn-xray.service >/dev/null 2>&1 || true

say "Устанавливаю совместимый Xray-core..."
sudo /usr/local/sbin/vpnctl core-update

ok "${APP_NAME} установлен."
echo
echo "Команда: vpn"
echo "Конфиги: ${CONFIG_DIR}"
echo
echo "Начать:"
echo "  vpn list"
echo "  vpn on"
echo
echo "Обновление в будущем:"
echo "  vpn update"
