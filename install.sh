#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
export PATH="${HOME}/.cargo/bin:${PATH}"

need_rustup=0
if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
    need_rustup=1
else
    ver="$(rustc -V | awk '{print $2}')"
    major="${ver%%.*}"
    rest="${ver#*.}"
    minor="${rest%%.*}"
    if [ "${major:-0}" -lt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -lt 85 ]; }; then
        echo "Системный rustc ${ver} устарел (требуется >= 1.85), ставлю актуальный toolchain через rustup..."
        need_rustup=1
    fi
fi

if [ "$need_rustup" -eq 1 ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "Ошибка: для установки Rust >= 1.85 требуется curl (и компилятор gcc/cc)." >&2
        exit 1
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

if ! command -v mullvad >/dev/null 2>&1; then
    echo "Предупреждение: системный CLI mullvad не найден в PATH." >&2
fi

echo "[1/3] Сборка релизного бинарника mullvad-cli ($(rustc -V))..."
cd "${PROJECT_DIR}"
cargo build --release

echo "[2/3] Установка в ${INSTALL_DIR}/mullvad-cli..."
mkdir -p "${INSTALL_DIR}"
install -m 0755 "target/release/mullvad-cli" "${INSTALL_DIR}/mullvad-cli"

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if [[ "${1:-}" == "--with-systemd" ]]; then
        SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
        mkdir -p "${SYSTEMD_USER_DIR}"
        cat > "${SYSTEMD_USER_DIR}/mullvad-watchdog.service" <<UNIT
[Unit]
Description=Mullvad Multi-Account Auto-Reconnect Watchdog
After=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/mullvad-cli --watch
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
UNIT
        systemctl --user daemon-reload
        systemctl --user enable --now mullvad-watchdog.service
        echo "[3/3] Установлен и запущен systemd --user сервис mullvad-watchdog.service."
    else
        echo "[3/3] Готово. Для автозапуска демона выполните: ./install.sh --with-systemd"
    fi
else
    echo "[3/3] Готово (systemd не обнаружен — добавьте mullvad-cli --watch & в автозапуск вашего DE/WM)."
fi
