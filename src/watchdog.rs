use crate::config::{AppConfig, EvictionPolicy};
use crate::mullvad::{self, VpnState};
use crate::ping;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedSender, Semaphore};

const KICK_WINDOW_SECS: i64 = 300;            // Окно 5 минут для подсчёта киков
const MAX_KICKS_IN_WINDOW: usize = 3;         // 3 кика подряд -> карантин
const COOLDOWN_DURATION_SECS: i64 = 600;      // 10 минут анти-кик карантина
const EXPIRED_COOLDOWN_SECS: i64 = 3600;      // 60 минут паузы для просроченного ключа
const DEVICES_POLL_INTERVAL_SECS: i64 = 30;   // Опрос слотов X/5 каждые 30 сек
const EXPIRY_POLL_INTERVAL_SECS: i64 = 86400; // Опрос дней раз в 24 часа
const STALE_TUNNEL_THRESHOLD: usize = 2;      // 2 неудачных RTT подряд при Connected -> reconnect

static LAST_EXPIRED_LOG_TS: AtomicI64 = AtomicI64::new(0);
static STALE_TUNNEL_STRIKES: AtomicUsize = AtomicUsize::new(0);

pub fn log_event(tx: &Option<UnboundedSender<String>>, msg: impl Into<String>) {
    let formatted = format!("[{}] {}", Utc::now().format("%H:%M:%S"), msg.into());
    if let Some(sender) = tx {
        let _ = sender.send(formatted);
    } else {
        println!("{}", formatted);
    }
}

fn is_expired_by_cache(expires_at_raw: Option<&str>) -> bool {
    let Some(raw) = expires_at_raw else {
        return false;
    };
    if let Ok(dt) = DateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S %z") {
        return dt.with_timezone(&Utc) <= Utc::now();
    }
    false
}

/// Безопасный вызов из TUI (когда systemd-демон активен): берёт flock ДО чтения config.toml
pub async fn refresh_pool_telemetry_locked(
    cfg: &mut AppConfig,
    active_key: Option<&str>,
    active_expires_at: Option<&str>,
    force_all: bool,
) -> bool {
    let _lock = match AppConfig::try_acquire_lock() {
        Some(l) => l,
        None => return false,
    };
    if let Ok(fresh) = AppConfig::load() {
        *cfg = fresh;
    }
    refresh_pool_telemetry(cfg, active_key, active_expires_at, force_all).await
}

/// Внутреннее обновление телеметрии (вызывается только при уже взятом ProcessLock)
pub async fn refresh_pool_telemetry(
    cfg: &mut AppConfig,
    active_key: Option<&str>,
    active_expires_at: Option<&str>,
    force_all: bool,
) -> bool {
    let now = Utc::now().timestamp();
    let mut dirty = false;

    // 1. Обновляем дату окончания для активного ключа (раз в сутки или при force_all)
    if let (Some(ak), Some(exp_str)) = (active_key, active_expires_at) {
        if let Some(acc) = cfg.accounts.iter_mut().find(|a| a.key == ak) {
            if force_all
                || acc.expires_at_raw.is_none()
                || now - acc.expiry_checked_ts >= EXPIRY_POLL_INTERVAL_SECS
            {
                acc.expires_at_raw = Some(exp_str.to_string());
                acc.expiry_checked_ts = now;
                dirty = true;
            }
        }
    }

    // 2. Обновляем число занятых слотов (X/5) по пулу через --account без смены сессии
    let due_indices: Vec<usize> = cfg
        .accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            force_all
                || a.cached_devices.is_none()
                || now - a.devices_checked_ts >= DEVICES_POLL_INTERVAL_SECS
        })
        .map(|(i, _)| i)
        .collect();

    if !due_indices.is_empty() {
        let sem = Arc::new(Semaphore::new(2));
        let mut tasks = Vec::with_capacity(due_indices.len());
        for idx in due_indices {
            let key = cfg.accounts[idx].key.clone();
            let permit = sem.clone().acquire_owned().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let count = mullvad::list_devices(Some(&key)).await.ok().map(|d| d.len());
                drop(permit);
                (idx, count)
            }));
        }

        for t in tasks {
            if let Ok((idx, Some(cnt))) = t.await {
                if let Some(acc) = cfg.accounts.get_mut(idx) {
                    acc.cached_devices = Some(cnt);
                    acc.devices_checked_ts = now;
                    dirty = true;
                }
            }
        }
    }

    // 3. Если туннель Disconnected — проверяем срок подписки только у ключей вне карантина и со свободными слотами
    if let Ok(st) = mullvad::get_status().await {
        if matches!(st.state, VpnState::Disconnected) {
            let orig_key = active_key.map(|s| s.to_string());
            let mut switched = false;
            for i in 0..cfg.accounts.len() {
                if !force_all && cfg.accounts[i].cooldown_until > now {
                    continue;
                }
                let need_check = force_all
                    || cfg.accounts[i].expires_at_raw.is_none()
                    || now - cfg.accounts[i].expiry_checked_ts >= EXPIRY_POLL_INTERVAL_SECS;
                let has_free_slot = cfg.accounts[i].cached_devices.map(|c| c < 5).unwrap_or(false);
                if need_check && has_free_slot {
                    let k = cfg.accounts[i].key.clone();
                    if let Ok(Ok(())) = mullvad::account_login(&k).await {
                        switched = true;
                        if let Ok(info) = mullvad::account_get().await {
                            if let Some(exp) = info.expires_at {
                                cfg.accounts[i].expires_at_raw = Some(exp);
                            }
                            cfg.accounts[i].expiry_checked_ts = now;
                            if info.is_expired {
                                cfg.accounts[i].cooldown_until = now + EXPIRED_COOLDOWN_SECS;
                            }
                            dirty = true;
                        }
                    }
                }
            }
            if switched {
                if let Some(ok_key) = orig_key {
                    let _ = mullvad::account_login(&ok_key).await;
                }
            }
        }
    }

    if dirty {
        let _ = cfg.save();
    }
    dirty
}

pub async fn enforce_profile(cfg: &AppConfig, log_tx: &Option<UnboundedSender<String>>) {
    if !cfg.profile.enforce_settings {
        return;
    }
    let current = mullvad::fetch_toggles().await;

    if let Some(want_mh) = cfg.profile.multihop {
        if current.multihop != want_mh {
            let _ = mullvad::set_multihop(want_mh).await;
            log_event(
                log_tx,
                format!("[INTERCEPT] Multihop -> {}", if want_mh { "ON" } else { "OFF" }),
            );
        }
    }
    if let Some(ref entry) = cfg.profile.entry_relay {
        let already = current.entry_relay.as_deref().map(|e| e.contains(entry)).unwrap_or(false);
        if !already {
            let _ = mullvad::set_entry_location(entry).await;
            log_event(log_tx, format!("[INTERCEPT] Entry -> {}", entry));
        }
    }
    if let Some(ref exit) = cfg.profile.exit_relay {
        let already = current.exit_relay.as_deref().map(|e| e.contains(exit)).unwrap_or(false);
        if !already {
            let _ = mullvad::set_exit_location(exit).await;
            log_event(log_tx, format!("[INTERCEPT] Exit -> {}", exit));
        }
    }
    if let Some(want_lock) = cfg.profile.lockdown {
        if current.lockdown != want_lock {
            let _ = mullvad::apply_toggle("lockdown", want_lock).await;
            log_event(
                log_tx,
                format!("[INTERCEPT] Lockdown -> {}", if want_lock { "ON" } else { "OFF" }),
            );
        }
    }
    if let Some(want_qr) = cfg.profile.quantum_resistant {
        if current.quantum_resistant != want_qr {
            let _ = mullvad::apply_toggle("quantum", want_qr).await;
            log_event(
                log_tx,
                format!("[INTERCEPT] Quantum -> {}", if want_qr { "ON" } else { "OFF" }),
            );
        }
    }
    if let Some(want_daita) = cfg.profile.daita {
        if current.daita != want_daita {
            let _ = mullvad::apply_toggle("daita", want_daita).await;
            log_event(log_tx, format!("[INTERCEPT] DAITA -> {}", if want_daita { "ON" } else { "OFF" }));
        }
    }
    if let Some(want_v6) = cfg.profile.ipv6 {
        if current.ipv6 != want_v6 {
            let _ = mullvad::apply_toggle("ipv6", want_v6).await;
            log_event(log_tx, format!("[INTERCEPT] IPv6 -> {}", if want_v6 { "ON" } else { "OFF" }));
        }
    }
}

fn register_kick_and_check_switch(
    cfg: &mut AppConfig,
    active_key: Option<&str>,
    log_tx: &Option<UnboundedSender<String>>,
) -> Option<usize> {
    let now = Utc::now().timestamp();
    let total = cfg.accounts.len();
    if total == 0 {
        return None;
    }

    let kicked_idx = if let Some(k) = active_key {
        cfg.accounts.iter().position(|a| a.key == k)
    } else {
        cfg.accounts
            .iter()
            .enumerate()
            .max_by_key(|(_, a)| a.last_used_ts)
            .filter(|(_, a)| a.last_used_ts > 0)
            .map(|(i, _)| i)
    }?;

    let acc = &mut cfg.accounts[kicked_idx];
    acc.kick_timestamps.retain(|&ts| now - ts <= KICK_WINDOW_SECS);
    acc.kick_timestamps.push(now);
    let count = acc.kick_timestamps.len();

    log_event(
        log_tx,
        format!(
            "KICK [{}/{} за 5 мин] на '{}' ({})",
            count,
            MAX_KICKS_IN_WINDOW,
            acc.label,
            AppConfig::mask_key(&acc.key)
        ),
    );

    if count >= MAX_KICKS_IN_WINDOW {
        acc.cooldown_until = now + COOLDOWN_DURATION_SECS;
        acc.kick_timestamps.clear();
        cfg.rr_index = (kicked_idx + 1) % total;
        log_event(
            log_tx,
            format!(
                "SWITCH: '{}' выбит {} раза за 5 мин -> карантин 10 мин, переход на следующий ключ!",
                acc.label, MAX_KICKS_IN_WINDOW
            ),
        );
        let _ = cfg.save();
        return Some(kicked_idx);
    }

    let _ = cfg.save();
    None
}

pub async fn ensure_connected(
    cfg: &mut AppConfig,
    log_tx: &Option<UnboundedSender<String>>,
    force: bool,
) -> Result<()> {
    let _lock = match AppConfig::try_acquire_lock() {
        Some(l) => l,
        None => return Ok(()),
    };

    if let Ok(fresh) = AppConfig::load() {
        *cfg = fresh;
    }

    enforce_profile(cfg, log_tx).await;

    if cfg.accounts.is_empty() {
        return Ok(());
    }

    let status = mullvad::get_status().await?;
    let acc_info = mullvad::account_get().await?;
    let now = Utc::now().timestamp();

    refresh_pool_telemetry(
        cfg,
        acc_info.account_number.as_deref(),
        acc_info.expires_at.as_deref(),
        false,
    )
    .await;

    let session_invalid = acc_info.account_number.is_none() || acc_info.is_expired;
    let needs_recovery = match &status.state {
        VpnState::Connected => session_invalid,
        VpnState::Connecting => false,
        VpnState::Disconnected => force || session_invalid,
        VpnState::Blocked(reason) => {
            let low = reason.to_lowercase();
            low.contains("account") || low.contains("device") || low.contains("time") || force
        }
        VpnState::Unknown(_) => force,
    };

    if !needs_recovery {
        // Wake-Heal: если статус Connected, проверяем сквозной RTT туннеля против зависания после сна
        if matches!(status.state, VpnState::Connected) {
            if ping::measure_active_tunnel_rtt().await.is_some() {
                STALE_TUNNEL_STRIKES.store(0, Ordering::Relaxed);
            } else {
                let strikes = STALE_TUNNEL_STRIKES.fetch_add(1, Ordering::Relaxed) + 1;
                if strikes >= STALE_TUNNEL_THRESHOLD {
                    STALE_TUNNEL_STRIKES.store(0, Ordering::Relaxed);
                    log_event(
                        log_tx,
                        format!(
                            "[WAKE-HEAL] Туннель Connected, но сквозной RTT не отвечает ({}/{}) -> mullvad reconnect...",
                            strikes, STALE_TUNNEL_THRESHOLD
                        ),
                    );
                    let _ = mullvad::reconnect().await;
                }
            }
        } else {
            STALE_TUNNEL_STRIKES.store(0, Ordering::Relaxed);
        }
        return Ok(());
    }

    STALE_TUNNEL_STRIKES.store(0, Ordering::Relaxed);

    // Если текущий залогиненный аккаунт просрочен — ставим ему паузу 60 мин и НЕ считаем это киком
    if acc_info.is_expired {
        if let Some(ref cur_key) = acc_info.account_number {
            let mut expired_label = None;
            if let Some(acc) = cfg.accounts.iter_mut().find(|a| &a.key == cur_key) {
                if acc.cooldown_until <= now {
                    acc.expires_at_raw = acc_info.expires_at.clone();
                    acc.expiry_checked_ts = now;
                    acc.cooldown_until = now + EXPIRED_COOLDOWN_SECS;
                    expired_label = Some(acc.label.clone());
                }
            }
            if let Some(lbl) = expired_label {
                let _ = cfg.save();
                log_event(
                    log_tx,
                    format!("EXPIRED: Аккаунт '{}' просрочен -> пауза 60 мин.", lbl),
                );
            }
        }
    }

    let mut avoid_idx = None;
    if !force && !acc_info.is_expired {
        avoid_idx = register_kick_and_check_switch(cfg, acc_info.account_number.as_deref(), log_tx);
    }

    let total = cfg.accounts.len();

    // Сбрасываем карантин только если ВСЕ аккаунты находятся в коротком анти-кик карантине (не просрочены)
    let all_in_kick_cooldown = total > 0
        && cfg
            .accounts
            .iter()
            .all(|a| a.cooldown_until > now && !is_expired_by_cache(a.expires_at_raw.as_deref()));

    if all_in_kick_cooldown {
        for a in &mut cfg.accounts {
            a.cooldown_until = 0;
            a.kick_timestamps.clear();
        }
        let _ = cfg.save();
        log_event(
            log_tx,
            "RESET: Все аккаунты в анти-кик карантине -> вывод пула из карантина.",
        );
    }

    // Флаг: есть ли среди НЕпросроченных ключей те, у кого заполнены все 5/5 слотов
    let mut has_full_valid_account = false;

    // Шаг 1: Поиск свободного действующего аккаунта (< 5 устройств)
    for offset in 0..total {
        let idx = (cfg.rr_index + offset) % total;
        if !force {
            if avoid_idx == Some(idx) && total > 1 {
                continue;
            }
            if cfg.accounts[idx].cooldown_until > now {
                continue;
            }
            if is_expired_by_cache(cfg.accounts[idx].expires_at_raw.as_deref()) {
                cfg.accounts[idx].cooldown_until = now + EXPIRED_COOLDOWN_SECS;
                let _ = cfg.save();
                continue;
            }
        }

        let acc = cfg.accounts[idx].clone();
        if let Ok(devs) = mullvad::list_devices(Some(&acc.key)).await {
            cfg.accounts[idx].cached_devices = Some(devs.len());
            cfg.accounts[idx].devices_checked_ts = now;
            if devs.len() >= 5 {
                if !is_expired_by_cache(cfg.accounts[idx].expires_at_raw.as_deref()) {
                    has_full_valid_account = true;
                }
                log_event(log_tx, format!("SKIP: '{}' заполнен (5/5 устройств).", acc.label));
                continue;
            }
        }

        match mullvad::account_login(&acc.key).await? {
            Ok(()) => {
                let info = mullvad::account_get().await?;
                if info.is_expired {
                    cfg.accounts[idx].expires_at_raw = info.expires_at.clone();
                    cfg.accounts[idx].expiry_checked_ts = now;
                    cfg.accounts[idx].cooldown_until = now + EXPIRED_COOLDOWN_SECS;
                    let _ = cfg.save();
                    log_event(
                        log_tx,
                        format!("EXPIRED: Аккаунт '{}' просрочен -> пауза 60 мин.", acc.label),
                    );
                    continue;
                }
                cfg.accounts[idx].last_used_ts = Utc::now().timestamp();
                cfg.accounts[idx].expires_at_raw = info.expires_at.clone();
                cfg.accounts[idx].expiry_checked_ts = now;
                cfg.accounts[idx].cooldown_until = 0;
                cfg.rr_index = idx;
                cfg.save()?;

                enforce_profile(cfg, log_tx).await;
                mullvad::connect().await?;
                log_event(
                    log_tx,
                    format!("OK: Подключено через '{}' ({:?})", acc.label, info.device_name),
                );
                return Ok(());
            }
            Err(err) => {
                log_event(
                    log_tx,
                    format!("ERR: '{}' -> {}", acc.label, err.lines().next().unwrap_or("")),
                );
            }
        }
    }

    // Если ни один действующий аккаунт не упёрся в 5/5 (например, все ключи просрочены) — уходим в тихую паузу
    if !has_full_valid_account {
        let last_log = LAST_EXPIRED_LOG_TS.load(Ordering::Relaxed);
        if force || now - last_log >= 300 {
            LAST_EXPIRED_LOG_TS.store(now, Ordering::Relaxed);
            log_event(
                log_tx,
                "PAUSE: Нет активных оплаченных ключей (все просрочены или на паузе). Авто-повтор через 60 мин.",
            );
        }
        return Ok(());
    }

    // Шаг 2: Выбивание слота (строго среди НЕпросроченных ключей с 5/5)
    let eligible_indices: Vec<usize> = (0..total)
        .filter(|&i| {
            let not_expired = !is_expired_by_cache(cfg.accounts[i].expires_at_raw.as_deref());
            if force {
                return not_expired;
            }
            if total == 1 {
                return not_expired && cfg.accounts[i].cooldown_until <= now;
            }
            not_expired && avoid_idx != Some(i) && cfg.accounts[i].cooldown_until <= now
        })
        .collect();

    if eligible_indices.is_empty() {
        return Ok(());
    }

    let target_idx = match cfg.eviction_policy {
        EvictionPolicy::RoundRobin => *eligible_indices
            .iter()
            .find(|&&i| i >= cfg.rr_index)
            .unwrap_or(&eligible_indices[0]),
        EvictionPolicy::OldestDevice => *eligible_indices
            .iter()
            .min_by_key(|&&i| cfg.accounts[i].last_used_ts)
            .unwrap_or(&eligible_indices[0]),
    };

    let target_acc = cfg.accounts[target_idx].clone();
    log_event(
        log_tx,
        format!(
            "EVICT: Все активные слоты заняты (5/5). Отзыв устройства на '{}' ({})...",
            target_acc.label,
            AppConfig::mask_key(&target_acc.key)
        ),
    );

    if let Ok(devices) = mullvad::list_devices(Some(&target_acc.key)).await {
        if let Some(victim) = devices.iter().find(|d| {
            !d.is_current
                && !cfg
                    .whitelist_devices
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(&d.name))
        }) {
            log_event(log_tx, format!("REVOKE: Удаляем '{}'...", victim.name));
            mullvad::revoke_device(&victim.name, Some(&target_acc.key)).await?;

            if let Ok(Ok(())) = mullvad::account_login(&target_acc.key).await {
                let info = mullvad::account_get().await.ok();
                if info.as_ref().map(|i| i.is_expired).unwrap_or(false) {
                    cfg.accounts[target_idx].expires_at_raw = info.and_then(|i| i.expires_at);
                    cfg.accounts[target_idx].expiry_checked_ts = now;
                    cfg.accounts[target_idx].cooldown_until = now + EXPIRED_COOLDOWN_SECS;
                    let _ = cfg.save();
                    log_event(
                        log_tx,
                        format!("EXPIRED: Аккаунт '{}' просрочен -> пауза 60 мин.", target_acc.label),
                    );
                    return Ok(());
                }
                cfg.accounts[target_idx].last_used_ts = Utc::now().timestamp();
                if let Some(ref inf) = info {
                    cfg.accounts[target_idx].expires_at_raw = inf.expires_at.clone();
                    cfg.accounts[target_idx].expiry_checked_ts = now;
                }
                cfg.accounts[target_idx].cooldown_until = 0;
                cfg.rr_index = target_idx;
                cfg.save()?;

                enforce_profile(cfg, log_tx).await;
                mullvad::connect().await?;
                log_event(
                    log_tx,
                    format!("OK: Слот освобождён, подключено через '{}'.", target_acc.label),
                );
            }
        } else {
            log_event(log_tx, "ERROR: Нет устройств вне whitelist_devices для отзыва.");
        }
    }

    Ok(())
}
