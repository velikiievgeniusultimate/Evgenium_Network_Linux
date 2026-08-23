from pathlib import Path

p = Path('install.sh')
s = p.read_text()
old = '''else
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
'''
new = '''else
    command -v dnf >/dev/null 2>&1 || die "Fedora обнаружена, но dnf не найден."
    command -v rpm >/dev/null 2>&1 || die "Fedora обнаружена, но rpm не найден."

    # Keep the VPN bootstrap independent from a full Fedora/KDE upgrade.
    # Fedora ships the qml-qt6 runner in qt6-qtdeclarative-devel. Installing the
    # newest devel package on a not-yet-updated Plasma image can otherwise pull a
    # large Qt/KDE upgrade and hit RPM file conflicts. Install the ordinary
    # runtime dependencies first, then request the devel package matching the
    # already-installed qt6-qtdeclarative NEVRA.
    packages=(python3 curl nftables iproute ca-certificates shadow-utils)
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
'''
if old not in s:
    if new in s:
        raise SystemExit('already patched')
    raise SystemExit('expected Fedora dependency block not found')
s = s.replace(old, new, 1)
p.write_text(s)
