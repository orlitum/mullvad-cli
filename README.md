<p align="center">
  <img src="assets/logo.svg" width="140" height="140" alt="mullvad-cli emblem">
</p>

<h1 align="center">mullvad-cli</h1>

<p align="center">
  Multi-account Terminal UI (TUI) and systemd watchdog daemon for Mullvad VPN built in Rust.<br>
  Automates device-slot eviction, anti-kick rotation, Wake-Heal recovery, and Multihop routing.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-2EA043?style=flat-square&logo=linux&logoColor=white" alt="Platform Linux">
  <img src="https://img.shields.io/badge/Rust-1.75%2B-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/Backend-Mullvad_CLI-192E45?style=flat-square" alt="Backend Mullvad CLI">
  <img src="https://img.shields.io/badge/License-MIT-0969DA?style=flat-square" alt="License MIT">
</p>

---

## Key Capabilities

* **Multi-Account Pool (`N` Keys):** Stores account numbers locally in `~/.config/mullvad-cli/config.toml` (`0600` permissions) with live `[X/5]` slot counters and `[Xd]` remaining subscription tracking.
* **Anti-Kick Circuit Breaker & Slot Eviction:** Isolates contested keys on a 10-minute cooldown after 3 kicks within 5 minutes, automatically revokes the oldest non-whitelisted device when all active accounts reach `5/5`, and pauses expired keys for 60 minutes without login loops.
* **Wake-Heal & Profile Enforcement (`[LOCKED]` / `[FREE]`):** Monitors end-to-end tunnel RTT to trigger `mullvad reconnect` after suspend/resume stalls and enforces `Entry -> Exit` Multihop, Lockdown Mode, Quantum-resistant tunnels, DAITA, and IPv6.
* **Inter-Process Synchronization:** Uses non-blocking OS-level `flock` locking and atomic config writes so the interactive TUI and background `mullvad-watchdog.service` operate concurrently without race conditions.
* **Parallel Relay Benchmark:** Measures TCP latency across Mullvad relays and tests `Entry -> Exit` Multihop pairs without dropping the active tunnel.

---

## Quick Start

```bash
git clone https://github.com/orlitum/mullvad-cli.git
cd mullvad-cli
chmod +x install.sh
./install.sh --with-systemd
```

Launch the interactive TUI control panel:

```bash
mullvad-cli
```

*(Optional: copy `config.example.toml` to `~/.config/mullvad-cli/config.toml` or use the built-in first-run onboarding wizard.)*

---

## CLI Flags & TUI Keybindings

| Command / Key | Action |
|---|---|
| `mullvad-cli --watch` | Run headless auto-recovery watchdog daemon |
| `mullvad-cli --add-key <16_DIGITS> --label "Main"` | Add an account key to the pool via CLI |
| `mullvad-cli --ping` | Benchmark TCP latency across Mullvad relays |
| `mullvad-cli --test-route "ee tll" "no osl"` | Measure latency for a specific `Entry -> Exit` pair |
| `1` / `2` / `3` / `Tab` | Switch tabs (`Accounts & Slots`, `Relays & Multihop`, `Settings`) |
| `a` / `x` / `u` | Add key / remove key / refresh `[X/5]` slots and `[Xd]` days |
| `e` / `Enter` | Set `Entry (Hop 1)` / set `Exit (Hop 2)` relay |
| `p` / `t` | Benchmark all relays / test selected `Entry -> Exit` route |
| `c` / `d` / `r` | Auto-Connect (with slot eviction) / Disconnect / Reconnect |
| `w` | Toggle profile enforcement (`[LOCKED]` ↔ `[FREE]`) |

---

## Disclaimer & Trademarks

This is an **unofficial, independent third-party utility** and is not affiliated with, endorsed by, or sponsored by **Mullvad VPN AB**.
**Mullvad** is a registered trademark of **Mullvad VPN AB** ([mullvad.net](https://mullvad.net)). This project requires the official Mullvad VPN client (`mullvad-daemon` and `mullvad` CLI) to be installed on your system; users are responsible for complying with Mullvad VPN AB's Terms of Service.
