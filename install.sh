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

# Recovery always downloads the current release. Never execute the installed
# manager: it may be too old, missing, or only partially upgraded.
case "${1:-}" in
    ""|--repair|--reinstall) ;;
    --help|-h)
        echo "Установка/восстановление: bash install.sh [--repair|--reinstall]"
        echo "Заново устанавливает CLI, GUI и зависимости; сохраняет токен, ключи и исключения."
        exit 0 ;;
    *) die "Неизвестный параметр: $1" ;;
esac
[[ $# -le 1 ]] || die "Слишком много параметров."

# BEGIN ARCH DEPENDENCY INSTALL
arch_install_dependencies() (
    # pacman refuses every -S transaction if any configured sync DB is absent.
    # Resolve Includes with pacman's own parser; retain options and usable repos.
    # Never edit pacman.conf, weaken signatures, or refresh only part of the DBs.
    command -v pacman-conf >/dev/null 2>&1 || die "Не найден pacman-conf из пакета pacman."
    dep_tmp="$(mktemp -d)"
    trap 'rm -rf "$dep_tmp"' EXIT
    pacman-conf > "$dep_tmp/resolved.conf" || die "Не удалось прочитать настройки pacman."
    db_path="$(pacman-conf DBPath)" || die "Не удалось определить каталог баз pacman."
    [[ -n "$db_path" && "$db_path" = /* ]] || die "Некорректный DBPath pacman."
    keep_section=1
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[([^]]+)\]$ ]]; then
            repo="${BASH_REMATCH[1]}"
            keep_section=1
            if [[ "$repo" != options && ! -f "${db_path%/}/sync/${repo}.db" ]]; then
                case "$repo" in
                    core|extra|multilib|community|core-testing|extra-testing|multilib-testing|community-testing|core-staging|extra-staging|multilib-staging|testing|staging|alarm)
                        die "Нет базы официального репозитория ${repo}. Сначала исправьте репозитории и выполните полное обновление Arch (sudo pacman -Syu), затем повторите --repair." ;;
                    *)
                        warn "Нет базы стороннего репозитория ${repo}: пропускаю его только для установки зависимостей VPN."
                        keep_section=0 ;;
                esac
            fi
        fi
        if ((keep_section)); then printf '%s\n' "$line"; fi
    done < "$dep_tmp/resolved.conf" > "$dep_tmp/pacman.conf"
    sudo pacman --config "$dep_tmp/pacman.conf" -S --needed --noconfirm "$@"
)
# END ARCH DEPENDENCY INSTALL

say "Обнаружена система: ${DISTRO}. Получаю sudo для установки/восстановления..."
sudo -v

say "Проверяю зависимости..."
if [[ "$DISTRO" == "arch" ]]; then
    command -v pacman >/dev/null 2>&1 || die "Arch обнаружен, но pacman не найден."
    packages=(python curl nftables iproute2 ca-certificates qt6-declarative strongswan openssl conntrack-tools)
    missing=()
    for p in "${packages[@]}"; do
        pacman -Q "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if ((${#missing[@]})); then
        say "Устанавливаю официальные Arch-пакеты: ${missing[*]}"
        arch_install_dependencies "${missing[@]}"
    else
        ok "Зависимости Arch уже установлены."
    fi
else
    command -v dnf >/dev/null 2>&1 || die "Fedora обнаружена, но dnf не найден."
    command -v rpm >/dev/null 2>&1 || die "Fedora обнаружена, но rpm не найден."

    # Keep the VPN bootstrap independent from a full Fedora/KDE upgrade.
    # Fedora ships the qml-qt6 runner in qt6-qtdeclarative-devel. Installing the
    # newest devel package on a not-yet-updated Plasma image can otherwise pull a
    # large Qt/KDE upgrade and hit RPM file conflicts. Install the ordinary
    # runtime dependencies first, then request the devel package matching the
    # already-installed qt6-qtdeclarative NEVRA.
    packages=(python3 curl nftables iproute ca-certificates shadow-utils strongswan openssl conntrack-tools)
    missing=()
    for p in "${packages[@]}"; do
        rpm -q "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if ((${#missing[@]})); then
        say "Устанавливаю официальные Fedora-пакеты: ${missing[*]}"
        sudo dnf install -y --no-best --setopt=install_weak_deps=False "${missing[@]}"
    else
        ok "Базовые зависимости Fedora уже установлены."
    fi

    QML_RUNTIME=""
    for candidate in /usr/bin/qml6 /usr/bin/qml-qt6 /usr/lib/qt6/bin/qml /usr/lib64/qt6/bin/qml /usr/bin/qml; do
        if [[ -x "$candidate" ]]; then
            QML_RUNTIME="$candidate"
            break
        fi
    done

    if [[ -z "$QML_RUNTIME" ]]; then
        QT_DECL_VERSION="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' qt6-qtdeclarative 2>/dev/null || true)"
        [[ -n "$QT_DECL_VERSION" ]] || die "Fedora KDE не содержит qt6-qtdeclarative; не могу подобрать совместимый QML runner."
        QT_DECL_DEVEL="qt6-qtdeclarative-devel-${QT_DECL_VERSION}"
        say "Устанавливаю QML runner той же версии, что и текущий Qt: ${QT_DECL_DEVEL}"
        if ! sudo dnf install -y --no-best --setopt=install_weak_deps=False "$QT_DECL_DEVEL"; then
            die "Не удалось установить совместимый QML runner без обновления всего KDE. Сначала синхронизируй Fedora пакетами 'sudo dnf distro-sync --refresh', затем повтори установщик."
        fi
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
sudo install -d -m 0755 /var/lib/vpn-manager
sudo install -d -o vpn-xray -g vpn-xray -m 0750 /var/lib/vpn-manager/xray

# On SELinux-enabled Fedora, restore the distribution-defined labels for the
# application directories. Arch simply skips this because restorecon is absent.
if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager >/dev/null 2>&1 || true
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
    if names != allowed or len(members) != len(allowed):
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

# The staged files are new, but user data stays in place. Keep a private backup
# before repairing settings or pointers; never remove the currently running release.
say "Сохраняю пользовательские данные и устанавливаю свежие файлы..."
sudo "$PYTHON_BIN" - "$OWNER_USER" "$OWNER_HOME" "$XRAY_UID" "$XRAY_GID" "$MANIFEST_URL" "${tmp}/release" <<'PY'
import fcntl, json, os, pathlib, pwd, shutil, sys, tarfile, tempfile, time
user, home, uid, gid, manifest, source = sys.argv[1:]
root = pathlib.Path('/opt/vpn-manager')
settings = pathlib.Path('/etc/vpn-manager/settings.json')
runtime = pathlib.Path('/run/vpn-manager')
runtime.mkdir(mode=0o750, parents=True, exist_ok=True)
lock = (runtime/'operation.lock').open('a+')
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit('Другая операция VPN ещё работает. Повторите установщик после её завершения.')
account = pwd.getpwnam(user)
if pathlib.Path(home).resolve() != pathlib.Path(account.pw_dir).resolve():
    raise SystemExit('HOME не совпадает с домашней папкой пользователя.')
data = {}
if settings.exists():
    try:
        data = json.loads(settings.read_text())
        if not isinstance(data, dict):
            data = {}
    except (ValueError, UnicodeError):
        pass  # Preserve the broken file in the backup, then rebuild settings.
if data.get('owner_user', user) != user or data.get('owner_home', home) != home:
    raise SystemExit('Запустите восстановление от владельца существующей установки.')
backups = pathlib.Path('/var/lib/vpn-manager/backups')
backups.mkdir(mode=0o700, parents=True, exist_ok=True)
backups.chmod(0o700)
fd, name = tempfile.mkstemp(prefix=time.strftime('reinstall-%Y%m%d-%H%M%S-'), suffix='.tar.gz', dir=backups)
os.close(fd)
with tarfile.open(name, 'w:gz') as tar:
    for path in [settings.parent, pathlib.Path(home)/'Vpn', root/'current', root/'previous',
                 pathlib.Path(home)/'.local/share/evgenium-network',
                 pathlib.Path(home)/'.local/share/plasma/plasmoids/com.evgenium.network']:
        if path.exists() or path.is_symlink():
            tar.add(path, arcname=str(path).lstrip('/'), recursive=True)
print('Резервная копия данных: '+name)
# Retain every existing setting and credential; only fill absent bootstrap fields.
for key, value in {'schema':2, 'engine':'token-ipsec', 'owner_user':user, 'owner_home':home,
                   'config_dir':home+'/Vpn/VPN configs', 'direct_sites':home+'/Vpn/DIRECT sites.txt',
                   'direct_networks':home+'/Vpn/DIRECT networks.txt', 'direct_apps':home+'/Vpn/DIRECT apps.txt'}.items():
    data.setdefault(key, value)
data.update(xray_uid=int(uid), xray_gid=int(gid), manager_manifest_url=manifest)
fd, name = tempfile.mkstemp(prefix='.settings-', dir=settings.parent)
with os.fdopen(fd, 'w') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write('\n'); f.flush(); os.fsync(f.fileno())
os.chmod(name, 0o600)
os.replace(name, settings)
version = (pathlib.Path(source)/'VERSION').read_text().strip()
dest = pathlib.Path(tempfile.mkdtemp(prefix=version+'-install-', dir=root/'releases'))
for filename in ('vpnctl.py', 'vpnadmin.py', 'VERSION'):
    shutil.copy2(pathlib.Path(source)/filename, dest/filename)
dest.chmod(0o755)
def link(target, path):
    temp = path.with_name(path.name+'.install-new')
    temp.unlink(missing_ok=True)
    temp.symlink_to(target)
    os.replace(temp, path)
current = root/'current'
if current.exists():
    link(current.resolve(), root/'previous')
link(dest, current)
link(current/'vpnctl.py', pathlib.Path('/usr/local/sbin/vpnctl'))
link(current/'vpnadmin.py', pathlib.Path('/usr/local/sbin/vpn-manager-admin'))
PY

printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/vpnctl\n' "$OWNER_USER" > "${tmp}/sudoers"
sudo install -o root -g root -m 0440 "${tmp}/sudoers" /etc/sudoers.d/zz-evgenium-vpn
if command -v visudo >/dev/null 2>&1; then
    sudo visudo -cf /etc/sudoers.d/zz-evgenium-vpn >/dev/null || {
        sudo rm -f /etc/sudoers.d/zz-evgenium-vpn
        die "Проверка sudoers не прошла."
    }
else
    warn "visudo не найден; sudoers установлен без отдельной syntax-check."
fi

say "Устанавливаю systemd unit, GUI и команду vpn..."
if ! sudo /usr/local/sbin/vpnctl internal-sync; then
    die "Завершение установки прервано. Данные сохранены. Повторите эту команду с --repair; не удаляйте папки вручную."
fi

if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -RF /opt/vpn-manager /etc/vpn-manager /var/lib/vpn-manager >/dev/null 2>&1 || true
    for path in /usr/local/sbin/vpnctl /usr/local/sbin/vpn-manager-admin /usr/local/bin/vpn /usr/local/bin/evgenium-network; do
        if [[ -e "$path" || -L "$path" ]]; then
            sudo restorecon -F "$path" >/dev/null 2>&1 || true
        fi
    done
fi

say "Проверяю установленную версию..."
sudo /usr/local/sbin/vpnctl version

ok "${APP_NAME} ${VERSION} установлен/восстановлен на ${DISTRO}."
echo "Закройте старое окно Evgenium Network и откройте приложение заново."
echo
echo "Команда: vpn"
echo "Приложение KDE: Evgenium Network"
echo "Вход: клиентский токен в приложении Evgenium Network"
echo
echo "Начать:"
echo "  evgenium-network"
echo "  vpn on"
echo
echo "Обновление в будущем:"
echo "  vpn update"
