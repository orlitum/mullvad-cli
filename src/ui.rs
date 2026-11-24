use crate::config::AppConfig;
use crate::mullvad::{
    self, AccountInfo, ConnectionStatus, DeviceEntry, MullvadToggles, RelayNode, VpnState,
};
use crate::ping;
use crate::watchdog;
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState, Tabs,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::mpsc;

const MULLVAD_YELLOW: Color = Color::Rgb(255, 213, 36);
const MULLVAD_BLUE_DARK: Color = Color::Rgb(25, 46, 69);
const MULLVAD_BLUE_MID: Color = Color::Rgb(41, 77, 115);
const MOLE_FUR: Color = Color::Rgb(201, 146, 56);
const MOLE_NOSE: Color = Color::Rgb(245, 199, 126);
const STATUS_GREEN: Color = Color::Rgb(68, 209, 122);
const STATUS_RED: Color = Color::Rgb(255, 77, 77);
const STATUS_WARN: Color = Color::Rgb(255, 165, 0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenMode {
    Onboarding,
    Dashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingField {
    KeyInput,
    LabelInput,
    ToggleLockdown,
    ToggleQuantum,
    ToggleDns,
    ToggleAutoConnect,
    ToggleAutoIntercept,
    FinishButton,
}

impl OnboardingField {
    fn next(self) -> Self {
        match self {
            Self::KeyInput => Self::LabelInput,
            Self::LabelInput => Self::ToggleLockdown,
            Self::ToggleLockdown => Self::ToggleQuantum,
            Self::ToggleQuantum => Self::ToggleDns,
            Self::ToggleDns => Self::ToggleAutoConnect,
            Self::ToggleAutoConnect => Self::ToggleAutoIntercept,
            Self::ToggleAutoIntercept => Self::FinishButton,
            Self::FinishButton => Self::KeyInput,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::KeyInput => Self::FinishButton,
            Self::LabelInput => Self::KeyInput,
            Self::ToggleLockdown => Self::LabelInput,
            Self::ToggleQuantum => Self::ToggleLockdown,
            Self::ToggleDns => Self::ToggleQuantum,
            Self::ToggleAutoConnect => Self::ToggleDns,
            Self::ToggleAutoIntercept => Self::ToggleAutoConnect,
            Self::FinishButton => Self::ToggleAutoIntercept,
        }
    }
}

pub struct OnboardingState {
    pub field: OnboardingField,
    pub key_buf: String,
    pub label_buf: String,
    pub lockdown: bool,
    pub quantum: bool,
    pub dns_block: bool,
    pub auto_connect: bool,
    pub auto_intercept: bool,
    pub notice: Option<String>,
}

impl Default for OnboardingState {
    fn default() -> Self {
        Self {
            field: OnboardingField::KeyInput,
            key_buf: String::new(),
            label_buf: String::new(),
            lockdown: true,
            quantum: true,
            dns_block: true,
            auto_connect: true,
            auto_intercept: true,
            notice: None,
        }
    }
}

pub enum InputMode {
    Normal,
    AddKeyNumber,
    AddKeyLabel(String),
}

pub struct AppState {
    pub screen_mode: ScreenMode,
    pub onboarding: OnboardingState,
    pub config: AppConfig,
    pub status: ConnectionStatus,
    pub account_info: AccountInfo,
    pub devices: Vec<DeviceEntry>,
    pub toggles: MullvadToggles,
    pub relays: Vec<RelayNode>,
    pub live_ping_ms: Option<u64>,
    pub active_tab: usize,
    pub acc_list_state: ListState,
    pub relay_table_state: TableState,
    pub toggle_list_state: ListState,
    pub logs: Vec<String>,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub auto_watchdog: bool,
    pub systemd_active: bool,
    pub pinging: bool,
}

impl AppState {
    pub fn new(config: AppConfig, systemd_active: bool) -> Self {
        let is_first_run = config.accounts.is_empty();
        let mut acc_list_state = ListState::default();
        if !is_first_run {
            acc_list_state.select(Some(0));
        }
        let mut toggle_list_state = ListState::default();
        toggle_list_state.select(Some(0));
        let mut relay_table_state = TableState::default();
        relay_table_state.select(Some(0));

        Self {
            screen_mode: if is_first_run {
                ScreenMode::Onboarding
            } else {
                ScreenMode::Dashboard
            },
            onboarding: OnboardingState::default(),
            config,
            status: ConnectionStatus {
                state: VpnState::Disconnected,
                relay: None,
                location: None,
                ipv4: None,
                ipv6: None,
            },
            account_info: AccountInfo {
                account_number: None,
                device_name: None,
                expires_at: None,
                is_expired: false,
            },
            devices: Vec::new(),
            toggles: MullvadToggles::default(),
            relays: Vec::new(),
            live_ping_ms: None,
            active_tab: 0,
            acc_list_state,
            relay_table_state,
            toggle_list_state,
            logs: vec!["[INIT] Mullvad Multi-Account TUI готов (Multihop + Auto-Intercept).".to_string()],
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            auto_watchdog: !systemd_active,
            systemd_active,
            pinging: false,
        }
    }
}

async fn check_systemd_watchdog() -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "mullvad-watchdog.service"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn measure_tunnel_rtt() -> Option<u64> {
    if let Some(ms) = ping::measure_tcp_latency("10.64.0.1", 53, 500).await {
        return Some(ms);
    }
    ping::measure_tcp_latency("1.1.1.1", 53, 600).await
}

pub async fn run_tui(config: AppConfig) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
    let (ping_tx, mut ping_rx) = mpsc::unbounded_channel::<Vec<RelayNode>>();
    let sys_active = check_systemd_watchdog().await;
    let mut app = AppState::new(config, sys_active);

    if let Ok(relays) = mullvad::fetch_relays(usize::MAX).await {
        app.relays = relays;
    }

    let mut last_poll = Instant::now() - Duration::from_secs(10);

    loop {
        while let Ok(line) = log_rx.try_recv() {
            app.logs.push(line);
            if app.logs.len() > 100 {
                app.logs.remove(0);
            }
        }

        if let Ok(ranked) = ping_rx.try_recv() {
            app.relays = ranked;
            app.pinging = false;
            app.logs.push("[PING] Замер завершён и отсортирован по RTT.".to_string());
        }

        if app.screen_mode == ScreenMode::Dashboard
            && last_poll.elapsed() >= Duration::from_secs(app.config.check_interval_secs)
        {
            app.systemd_active = check_systemd_watchdog().await;
            if let Ok(st) = mullvad::get_status().await {
                if matches!(st.state, VpnState::Connected) {
                    app.live_ping_ms = measure_tunnel_rtt().await;
                } else {
                    app.live_ping_ms = None;
                }
                app.status = st;
            }
            if let Ok(info) = mullvad::account_get().await {
                app.account_info = info;
            }
            if let Ok(devs) = mullvad::list_devices(None).await {
                app.devices = devs;
            }
            app.toggles = mullvad::fetch_toggles().await;

            if app.auto_watchdog && !app.systemd_active {
                let tx_opt = Some(log_tx.clone());
                let _ = watchdog::ensure_connected(&mut app.config, &tx_opt, false).await;
            } else {
                let updated = watchdog::refresh_pool_telemetry_locked(
                    &mut app.config,
                    app.account_info.account_number.as_deref(),
                    app.account_info.expires_at.as_deref(),
                    false,
                )
                .await;
                if !updated {
                    if let Ok(fresh) = AppConfig::load() {
                        app.config = fresh;
                    }
                }
            }
            last_poll = Instant::now();
        }

        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                if app.screen_mode == ScreenMode::Onboarding {
                    if handle_onboarding_key(&mut app, key.code, &log_tx).await {
                        break;
                    }
                    continue;
                }

                match &app.input_mode {
                    InputMode::AddKeyNumber => match key.code {
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.input_buffer.clear();
                        }
                        KeyCode::Enter => {
                            let num = app.input_buffer.trim().to_string();
                            app.input_buffer.clear();
                            app.input_mode = InputMode::AddKeyLabel(num);
                        }
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        KeyCode::Char(c) => app.input_buffer.push(c),
                        _ => {}
                    },
                    InputMode::AddKeyLabel(num) => {
                        let num_clone = num.clone();
                        match key.code {
                            KeyCode::Esc => {
                                app.input_mode = InputMode::Normal;
                                app.input_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let label = if app.input_buffer.trim().is_empty() {
                                    format!("Acc #{}", app.config.accounts.len() + 1)
                                } else {
                                    app.input_buffer.trim().to_string()
                                };
                                match app.config.add_account(label.clone(), &num_clone) {
                                    Ok(()) => app.logs.push(format!("[ADD] Добавлен ключ '{}'", label)),
                                    Err(e) => app.logs.push(format!("[ERR] {}", e)),
                                }
                                app.input_mode = InputMode::Normal;
                                app.input_buffer.clear();
                            }
                            KeyCode::Backspace => {
                                app.input_buffer.pop();
                            }
                            KeyCode::Char(c) => app.input_buffer.push(c),
                            _ => {}
                        }
                    }
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab | KeyCode::Right => app.active_tab = (app.active_tab + 1) % 3,
                        KeyCode::Left => app.active_tab = (app.active_tab + 2) % 3,
                        KeyCode::Char('1') => app.active_tab = 0,
                        KeyCode::Char('2') => app.active_tab = 1,
                        KeyCode::Char('3') => app.active_tab = 2,
                        KeyCode::Char('c') => {
                            let tx_opt = Some(log_tx.clone());
                            let _ = watchdog::ensure_connected(&mut app.config, &tx_opt, true).await;
                        }
                        KeyCode::Char('d') => {
                            let _ = mullvad::disconnect().await;
                            app.logs.push("[CMD] Отключение VPN...".to_string());
                        }
                        KeyCode::Char('r') => {
                            let _ = mullvad::reconnect().await;
                            app.logs.push("[CMD] Переподключение...".to_string());
                        }
                        KeyCode::Char('w') => {
                            app.config.profile.enforce_settings = !app.config.profile.enforce_settings;
                            let _ = app.config.save();
                            app.logs.push(format!(
                                "[INTERCEPT] Авто-перехват профиля: {}",
                                if app.config.profile.enforce_settings { "ON" } else { "OFF" }
                            ));
                        }
                        KeyCode::Char('a') if app.active_tab == 0 => {
                            app.input_mode = InputMode::AddKeyNumber;
                            app.input_buffer.clear();
                        }
                        KeyCode::Char('u') if app.active_tab == 0 => {
                            app.logs.push("[SYNC] Обновление слотов и остатка дней по пулу...".to_string());
                            let _ = watchdog::refresh_pool_telemetry_locked(
                                &mut app.config,
                                app.account_info.account_number.as_deref(),
                                app.account_info.expires_at.as_deref(),
                                true,
                            )
                            .await;
                        }
                        KeyCode::Char('x') if app.active_tab == 0 => {
                            if let Some(idx) = app.acc_list_state.selected() {
                                if idx < app.config.accounts.len() {
                                    let removed = app.config.accounts.remove(idx);
                                    let _ = app.config.save();
                                    app.logs.push(format!("[DEL] Удалён '{}'", removed.label));
                                }
                            }
                        }
                        KeyCode::Char('m') if app.active_tab == 1 => {
                            let enable_mh = !app.toggles.multihop;
                            if enable_mh {
                                if let Some(ref entry) = app.config.profile.entry_relay {
                                    let _ = mullvad::set_entry_location(entry).await;
                                }
                                let _ = mullvad::set_multihop(true).await;
                                app.config.profile.multihop = Some(true);
                                app.logs.push("[MODE] Включён двойной прыжок (2-HOP).".to_string());
                            } else {
                                let _ = mullvad::set_multihop(false).await;
                                app.config.profile.multihop = Some(false);
                                app.logs.push("[MODE] Включён режим одного сервера (1-HOP).".to_string());
                            }
                            let _ = app.config.save();
                            let _ = mullvad::reconnect().await;
                        }
                        KeyCode::Char('e') if app.active_tab == 1 => {
                            if let Some(idx) = app.relay_table_state.selected() {
                                if let Some(r) = app.relays.get(idx).cloned() {
                                    let spec = format!("{} {} {}", r.country_code, r.city_code, r.hostname);
                                    let _ = mullvad::set_entry_location(&spec).await;
                                    app.config.profile.entry_relay = Some(spec);
                                    app.config.profile.multihop = Some(true);
                                    app.config.profile.enforce_settings = true;
                                    let _ = app.config.save();
                                    app.logs.push(format!(
                                        "[ENTRY] Входной сервер (Hop 1): {} ({}, {})",
                                        r.hostname, r.country_name, r.city_name
                                    ));
                                }
                            }
                        }
                        KeyCode::Char('p') if app.active_tab == 1 && !app.pinging => {
                            app.pinging = true;
                            app.logs.push("[PING] Замер задержки релеев в фоне...".to_string());
                            let relays_clone = app.relays.clone();
                            let tx_p = ping_tx.clone();
                            tokio::spawn(async move {
                                let bench = ping::benchmark_relays(relays_clone).await;
                                let _ = tx_p.send(bench);
                            });
                        }
                        KeyCode::Char('t') if app.active_tab == 1 => {
                            let entry_s = app
                                .config
                                .profile
                                .entry_relay
                                .clone()
                                .or_else(|| app.toggles.entry_relay.clone())
                                .unwrap_or_else(|| "se sto".to_string());
                            let exit_s = app
                                .config
                                .profile
                                .exit_relay
                                .clone()
                                .or_else(|| app.status.relay.clone())
                                .unwrap_or_else(|| "ch zrh".to_string());
                            let mut res = ping::check_entry_exit_pair(&app.relays, &entry_s, &exit_s).await;

                            if res.exit_ms.is_none() && matches!(app.status.state, VpnState::Connected) {
                                if let Some(active_relay) = &app.status.relay {
                                    if res.exit_label.contains(active_relay) || exit_s.contains(active_relay) {
                                        res.exit_ms = measure_tunnel_rtt().await;
                                    }
                                }
                            }

                            app.logs.push(format!(
                                "[ROUTE PING] Вход {} = {} ms | Выход {} = {} ms",
                                res.entry_label,
                                res.entry_ms.map(|m| m.to_string()).unwrap_or_else(|| "--".into()),
                                res.exit_label,
                                res.exit_ms.map(|m| m.to_string()).unwrap_or_else(|| "--".into()),
                            ));
                        }
                        KeyCode::Down | KeyCode::Char('j') => move_selection(&mut app, 1),
                        KeyCode::Up | KeyCode::Char('k') => move_selection(&mut app, -1),
                        KeyCode::Enter => handle_enter(&mut app, &log_tx).await,
                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

async fn handle_onboarding_key(
    app: &mut AppState,
    code: KeyCode,
    log_tx: &mpsc::UnboundedSender<String>,
) -> bool {
    match code {
        KeyCode::Esc => return true,
        KeyCode::Tab | KeyCode::Down => app.onboarding.field = app.onboarding.field.next(),
        KeyCode::BackTab | KeyCode::Up => app.onboarding.field = app.onboarding.field.prev(),
        KeyCode::F(5) => finish_onboarding(app, log_tx).await,
        KeyCode::Backspace => match app.onboarding.field {
            OnboardingField::KeyInput => {
                app.onboarding.key_buf.pop();
            }
            OnboardingField::LabelInput => {
                app.onboarding.label_buf.pop();
            }
            _ => {}
        },
        KeyCode::Char(' ') => match app.onboarding.field {
            OnboardingField::ToggleLockdown => app.onboarding.lockdown = !app.onboarding.lockdown,
            OnboardingField::ToggleQuantum => app.onboarding.quantum = !app.onboarding.quantum,
            OnboardingField::ToggleDns => app.onboarding.dns_block = !app.onboarding.dns_block,
            OnboardingField::ToggleAutoConnect => {
                app.onboarding.auto_connect = !app.onboarding.auto_connect
            }
            OnboardingField::ToggleAutoIntercept => {
                app.onboarding.auto_intercept = !app.onboarding.auto_intercept
            }
            OnboardingField::LabelInput => app.onboarding.label_buf.push(' '),
            OnboardingField::KeyInput => app.onboarding.key_buf.push(' '),
            OnboardingField::FinishButton => finish_onboarding(app, log_tx).await,
        },
        KeyCode::Char(c) => match app.onboarding.field {
            OnboardingField::KeyInput => app.onboarding.key_buf.push(c),
            OnboardingField::LabelInput => app.onboarding.label_buf.push(c),
            _ => {}
        },
        KeyCode::Enter => match app.onboarding.field {
            OnboardingField::KeyInput | OnboardingField::LabelInput => {
                if !app.onboarding.key_buf.trim().is_empty() {
                    let label = if app.onboarding.label_buf.trim().is_empty() {
                        format!("Acc #{}", app.config.accounts.len() + 1)
                    } else {
                        app.onboarding.label_buf.trim().to_string()
                    };
                    let key_raw = app.onboarding.key_buf.clone();
                    match app.config.add_account(label.clone(), &key_raw) {
                        Ok(()) => {
                            app.onboarding.notice = Some(format!(
                                "Добавлен ключ '{}' (всего: {}). Введите ещё или нажмите F5 для старта.",
                                label,
                                app.config.accounts.len()
                            ));
                            app.onboarding.key_buf.clear();
                            app.onboarding.label_buf.clear();
                            app.onboarding.field = OnboardingField::KeyInput;
                        }
                        Err(e) => app.onboarding.notice = Some(format!("Ошибка: {}", e)),
                    }
                } else if app.onboarding.field == OnboardingField::KeyInput {
                    app.onboarding.field = OnboardingField::ToggleLockdown;
                } else {
                    app.onboarding.field = app.onboarding.field.next();
                }
            }
            OnboardingField::ToggleLockdown => app.onboarding.lockdown = !app.onboarding.lockdown,
            OnboardingField::ToggleQuantum => app.onboarding.quantum = !app.onboarding.quantum,
            OnboardingField::ToggleDns => app.onboarding.dns_block = !app.onboarding.dns_block,
            OnboardingField::ToggleAutoConnect => {
                app.onboarding.auto_connect = !app.onboarding.auto_connect
            }
            OnboardingField::ToggleAutoIntercept => {
                app.onboarding.auto_intercept = !app.onboarding.auto_intercept
            }
            OnboardingField::FinishButton => finish_onboarding(app, log_tx).await,
        },
        _ => {}
    }
    false
}

async fn finish_onboarding(app: &mut AppState, log_tx: &mpsc::UnboundedSender<String>) {
    if !app.onboarding.key_buf.trim().is_empty() {
        let label = if app.onboarding.label_buf.trim().is_empty() {
            format!("Acc #{}", app.config.accounts.len() + 1)
        } else {
            app.onboarding.label_buf.trim().to_string()
        };
        if let Err(e) = app.config.add_account(label, &app.onboarding.key_buf.clone()) {
            app.onboarding.notice = Some(format!("Ошибка: {}", e));
            return;
        }
        app.onboarding.key_buf.clear();
        app.onboarding.label_buf.clear();
    }

    if app.config.accounts.is_empty() {
        app.onboarding.notice =
            Some("Добавьте хотя бы один 16-значный ключ Mullvad перед запуском.".to_string());
        app.onboarding.field = OnboardingField::KeyInput;
        return;
    }

    let _ = mullvad::apply_toggle("lockdown", app.onboarding.lockdown).await;
    let _ = mullvad::apply_toggle("quantum", app.onboarding.quantum).await;
    let _ = mullvad::apply_toggle("dns_ads", app.onboarding.dns_block).await;
    let _ = mullvad::apply_toggle("auto_connect", app.onboarding.auto_connect).await;

    app.config.profile.lockdown = Some(app.onboarding.lockdown);
    app.config.profile.quantum_resistant = Some(app.onboarding.quantum);
    app.config.profile.enforce_settings = app.onboarding.auto_intercept;
    let _ = app.config.save();

    app.acc_list_state.select(Some(0));
    app.screen_mode = ScreenMode::Dashboard;
    let _ = log_tx.send(format!(
        "[SETUP] Настройка завершена. Ключей в пуле: {}. Запуск автоподключения...",
        app.config.accounts.len()
    ));
    let tx_opt = Some(log_tx.clone());
    let _ = watchdog::ensure_connected(&mut app.config, &tx_opt, true).await;
}

fn move_selection(app: &mut AppState, delta: isize) {
    match app.active_tab {
        0 => {
            let len = app.config.accounts.len();
            if len == 0 {
                return;
            }
            let cur = app.acc_list_state.selected().unwrap_or(0) as isize;
            let next = (cur + delta).rem_euclid(len as isize) as usize;
            app.acc_list_state.select(Some(next));
        }
        1 => {
            let len = app.relays.len();
            if len == 0 {
                return;
            }
            let cur = app.relay_table_state.selected().unwrap_or(0) as isize;
            let next = (cur + delta).rem_euclid(len as isize) as usize;
            app.relay_table_state.select(Some(next));
        }
        2 => {
            let len = 8isize;
            let cur = app.toggle_list_state.selected().unwrap_or(0) as isize;
            let next = (cur + delta).rem_euclid(len) as usize;
            app.toggle_list_state.select(Some(next));
        }
        _ => {}
    }
}

async fn handle_enter(app: &mut AppState, log_tx: &mpsc::UnboundedSender<String>) {
    match app.active_tab {
        0 => {
            if let Some(idx) = app.acc_list_state.selected() {
                if let Some(acc) = app.config.accounts.get(idx).cloned() {
                    let _ = log_tx.send(format!("[LOGIN] Вход в '{}'...", acc.label));
                    match mullvad::account_login(&acc.key).await {
                        Ok(Ok(())) => {
                            let _ = mullvad::connect().await;
                            let _ = log_tx.send(format!("[OK] Подключено к '{}'", acc.label));
                        }
                        Ok(Err(e)) => {
                            let _ = log_tx.send(format!("[ERR] {}", e.lines().next().unwrap_or("")));
                        }
                        Err(e) => {
                            let _ = log_tx.send(format!("[ERR] {}", e));
                        }
                    }
                }
            }
        }
        1 => {
            if let Some(idx) = app.relay_table_state.selected() {
                if let Some(r) = app.relays.get(idx).cloned() {
                    let spec = format!("{} {} {}", r.country_code, r.city_code, r.hostname);
                    let _ = mullvad::set_exit_location(&spec).await;
                    app.config.profile.exit_relay = Some(spec);
                    app.config.profile.enforce_settings = true;
                    let _ = app.config.save();
                    let _ = mullvad::connect().await;
                    let _ = log_tx.send(format!(
                        "[EXIT] Выходной сервер (Hop 2): {} ({}, {})",
                        r.hostname, r.country_name, r.city_name
                    ));
                }
            }
        }
        2 => {
            if let Some(idx) = app.toggle_list_state.selected() {
                let (key, new_val) = match idx {
                    0 => {
                        app.config.profile.lockdown = Some(!app.toggles.lockdown);
                        ("lockdown", !app.toggles.lockdown)
                    }
                    1 => ("lan", !app.toggles.lan),
                    2 => {
                        app.config.profile.quantum_resistant = Some(!app.toggles.quantum_resistant);
                        ("quantum", !app.toggles.quantum_resistant)
                    }
                    3 => {
                        app.config.profile.daita = Some(!app.toggles.daita);
                        ("daita", !app.toggles.daita)
                    }
                    4 => {
                        app.config.profile.multihop = Some(!app.toggles.multihop);
                        ("multihop", !app.toggles.multihop)
                    }
                    5 => ("dns_ads", !app.toggles.dns_block_ads),
                    6 => ("auto_connect", !app.toggles.auto_connect),
                    7 => {
                        app.config.profile.ipv6 = Some(!app.toggles.ipv6);
                        ("ipv6", !app.toggles.ipv6)
                    }
                    _ => return,
                };
                let _ = app.config.save();
                let _ = mullvad::apply_toggle(key, new_val).await;
                let _ = log_tx.send(format!("[CFG] {} -> {}", key, if new_val { "ON" } else { "OFF" }));
            }
        }
        _ => {}
    }
}

fn draw_ui(f: &mut Frame, app: &mut AppState) {
    if app.screen_mode == ScreenMode::Onboarding {
        draw_onboarding(f, app);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_banner(f, app, chunks[0]);
    draw_tabs(f, app, chunks[1]);

    match app.active_tab {
        0 => draw_accounts_tab(f, app, chunks[2]),
        1 => draw_relays_tab(f, app, chunks[2]),
        2 => draw_toggles_tab(f, app, chunks[2]),
        _ => {}
    }

    draw_logs(f, app, chunks[3]);
    draw_footer(f, app, chunks[4]);
}

fn mullvad_mole_art() -> Vec<Line<'static>> {
    let bg = MULLVAD_BLUE_DARK;
    let yel = MULLVAD_YELLOW;
    let fur = MOLE_FUR;
    let nose = MOLE_NOSE;
    let wht = Color::White;

    let cell = |ch: &'static str, fg: Color, bg_c: Color| {
        Span::styled(ch, Style::default().fg(fg).bg(bg_c))
    };

    vec![
        Line::from(vec![
            cell("      ", bg, bg),
            cell("▄", yel, bg),
            cell("█", wht, bg),
            cell("████", yel, bg),
            cell("▄ ", bg, bg),
        ]),
        Line::from(vec![
            cell(" ", bg, bg),
            cell("▄", nose, bg),
            cell("  ▄▄", yel, bg),
            cell("█", wht, bg),
            cell("██████", yel, bg),
            cell(" ", bg, bg),
        ]),
        Line::from(vec![
            cell(" ", bg, bg),
            cell("▀", nose, bg),
            cell("████", fur, bg),
            cell("▀▀████", fur, yel),
            cell("▀ ", fur, bg),
        ]),
        Line::from(vec![
            cell("   ", bg, bg),
            cell("▀████", fur, bg),
            cell("▄", bg, fur),
            cell("█████", fur, bg),
            cell(" ", bg, bg),
        ]),
        Line::from(vec![
            cell("    ", bg, bg),
            cell("▄███████▄", fur, bg),
            cell(" ", bg, bg),
        ]),
    ]
}


fn draw_banner(f: &mut Frame, app: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MULLVAD_YELLOW))
        .style(Style::default().bg(MULLVAD_BLUE_DARK));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(16), Constraint::Min(30)])
        .split(inner);

    f.render_widget(Paragraph::new(mullvad_mole_art()), cols[0]);

    let (status_text, status_color) = match &app.status.state {
        VpnState::Connected => ("● CONNECTED", STATUS_GREEN),
        VpnState::Connecting => ("◐ CONNECTING...", STATUS_WARN),
        VpnState::Disconnected => ("○ DISCONNECTED", STATUS_RED),
        VpnState::Blocked(r) => (r.as_str(), STATUS_RED),
        VpnState::Unknown(r) => (r.as_str(), STATUS_WARN),
    };

    let masked = app
        .account_info
        .account_number
        .as_deref()
        .map(AppConfig::mask_key)
        .unwrap_or_else(|| "NOT LOGGED IN".to_string());

    let ping_str = app
        .live_ping_ms
        .map(|ms| format!("{} ms", ms))
        .unwrap_or_else(|| "-- ms".to_string());

    let full_route = app
        .status
        .relay
        .as_deref()
        .unwrap_or("none");

    let daemon_badge = if app.systemd_active {
        "[SYSTEMD DAEMON]"
    } else if app.auto_watchdog {
        "[TUI WATCHDOG]"
    } else {
        "[PAUSED]"
    };

    let info_lines = vec![
        Line::from(vec![
            Span::styled(
                " MULLVAD MULTI-ACCOUNT CLI ",
                Style::default()
                    .fg(MULLVAD_BLUE_DARK)
                    .bg(MULLVAD_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" v1.0.0  ", Style::default().fg(Color::Gray)),
            Span::styled(status_text, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(" Account: ", Style::default().fg(Color::Gray)),
            Span::styled(masked, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("   Device: ", Style::default().fg(Color::Gray)),
            Span::styled(
                app.account_info.device_name.as_deref().unwrap_or("-"),
                Style::default().fg(MULLVAD_YELLOW),
            ),
            Span::styled(
                format!(" ({}/5)", app.devices.len()),
                Style::default().fg(if app.devices.len() >= 5 { STATUS_WARN } else { STATUS_GREEN }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Route:   ", Style::default().fg(Color::Gray)),
            Span::styled(full_route, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" IPv4:    ", Style::default().fg(Color::Gray)),
            Span::styled(
                app.status.ipv4.as_deref().unwrap_or("0.0.0.0"),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if app.toggles.ipv6 { "  IPv6: " } else { "" },
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                if app.toggles.ipv6 {
                    app.status.ipv6.as_deref().unwrap_or("assigning...")
                } else {
                    ""
                },
                Style::default().fg(Color::Cyan),
            ),
            Span::styled("   Total Ping: ", Style::default().fg(Color::Gray)),
            Span::styled(
                ping_str,
                Style::default()
                    .fg(if app.live_ping_ms.is_some() { STATUS_GREEN } else { STATUS_RED })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Daemon:  ", Style::default().fg(Color::Gray)),
            Span::styled(
                daemon_badge,
                Style::default().fg(if app.systemd_active || app.auto_watchdog {
                    STATUS_GREEN
                } else {
                    STATUS_WARN
                }),
            ),
            Span::styled("   Intercept: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if app.config.profile.enforce_settings { "[LOCKED]" } else { "[FREE]" },
                Style::default().fg(if app.config.profile.enforce_settings {
                    MULLVAD_YELLOW
                } else {
                    Color::Gray
                }),
            ),
            Span::styled("   Exp: ", Style::default().fg(Color::Gray)),
            Span::styled(
                app.account_info.expires_at.as_deref().unwrap_or("-"),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(info_lines), cols[1]);
}

fn draw_tabs(f: &mut Frame, app: &AppState, area: Rect) {
    let titles = vec![
        " [1] Аккаунты & Слоты ",
        " [2] Релеи & Multihop (Entry -> Exit) ",
        " [3] Настройки Mullvad ",
    ];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
        )
        .select(app.active_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(MULLVAD_BLUE_DARK)
                .bg(MULLVAD_YELLOW)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn draw_accounts_tab(f: &mut Frame, app: &mut AppState, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let now_ts = chrono::Utc::now().timestamp();
    let items: Vec<ListItem> = app
        .config
        .accounts
        .iter()
        .map(|a| {
            let is_active = app.account_info.account_number.as_deref() == Some(a.key.as_str());
            let in_cooldown = a.cooldown_until > now_ts;
            let marker = if is_active {
                "★ "
            } else if in_cooldown {
                "⏳"
            } else {
                "  "
            };

            let slots_count = if is_active && !app.devices.is_empty() {
                Some(app.devices.len())
            } else {
                a.cached_devices
            };
            let slots_str = match slots_count {
                Some(n) => format!(" [{}/5]", n),
                None => " [?/5]".to_string(),
            };
            let slots_color = match slots_count {
                Some(n) if n >= 5 => STATUS_WARN,
                Some(_) => STATUS_GREEN,
                None => Color::DarkGray,
            };

            let days_str = match a.days_remaining() {
                Some(d) => format!(" [{}d]", d),
                None => String::new(),
            };

            let extra_tag = if in_cooldown {
                format!(" [CD {}m]", ((a.cooldown_until - now_ts) / 60).max(1))
            } else if !a.kick_timestamps.is_empty() {
                format!(" [kicks:{}/3]", a.kick_timestamps.len())
            } else {
                String::new()
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    marker,
                    Style::default().fg(if in_cooldown { STATUS_RED } else { MULLVAD_YELLOW }),
                ),
                Span::styled(
                    format!("{:<14}", a.label),
                    Style::default()
                        .fg(if in_cooldown { Color::DarkGray } else { Color::White })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(AppConfig::mask_key(&a.key), Style::default().fg(Color::Gray)),
                Span::styled(slots_str, Style::default().fg(slots_color).add_modifier(Modifier::BOLD)),
                Span::styled(days_str, Style::default().fg(Color::Cyan)),
                Span::styled(extra_tag, Style::default().fg(STATUS_WARN)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    " Пул ключей ({}) [a: добавить | x: удалить | Enter: вход] ",
                    app.config.accounts.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
        )
        .highlight_style(
            Style::default()
                .bg(MULLVAD_BLUE_MID)
                .fg(MULLVAD_YELLOW)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, cols[0], &mut app.acc_list_state);

    let dev_items: Vec<ListItem> = app
        .devices
        .iter()
        .map(|d| {
            let badge = if d.is_current { " [ЭТО УСТРОЙСТВО]" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled("• ", Style::default().fg(MULLVAD_YELLOW)),
                Span::styled(&d.name, Style::default().fg(Color::White)),
                Span::styled(badge, Style::default().fg(STATUS_GREEN)),
            ]))
        })
        .collect();

    let dev_list = List::new(dev_items).block(
        Block::default()
            .title(format!(" Активные слоты ({}/5 devices) ", app.devices.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.devices.len() >= 5 {
                STATUS_WARN
            } else {
                MULLVAD_BLUE_MID
            })),
    );
    f.render_widget(dev_list, cols[1]);
}

fn draw_relays_tab(f: &mut Frame, app: &mut AppState, area: Rect) {
    let rows: Vec<Row> = app
        .relays
        .iter()
        .map(|r| {
            let ping_cell = match r.latency_ms {
                Some(ms) => Cell::from(format!("{} ms", ms)).style(Style::default().fg(if ms < 60 {
                    STATUS_GREEN
                } else if ms < 130 {
                    STATUS_WARN
                } else {
                    STATUS_RED
                })),
                None => Cell::from("-").style(Style::default().fg(Color::DarkGray)),
            };
            Row::new(vec![
                Cell::from(r.country_name.clone()),
                Cell::from(r.city_name.clone()),
                Cell::from(r.hostname.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(r.ipv4.clone()),
                ping_cell,
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(22),
            Constraint::Percentage(22),
            Constraint::Percentage(24),
            Constraint::Percentage(18),
            Constraint::Percentage(14),
        ],
    )
    .header(
        Row::new(vec!["Страна", "Город", "Хостнейм", "IPv4", "Ping"])
            .style(Style::default().fg(MULLVAD_YELLOW).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Серверы [Enter: выбрать сервер | e: задать Вход (Hop 1) | m: 1-HOP/2-HOP | p: пинг] ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
    )
    .row_highlight_style(
        Style::default()
            .bg(MULLVAD_BLUE_MID)
            .fg(MULLVAD_YELLOW)
            .add_modifier(Modifier::BOLD),
    );

    f.render_stateful_widget(table, area, &mut app.relay_table_state);
}

fn draw_toggles_tab(f: &mut Frame, app: &mut AppState, area: Rect) {
    let entries = [
        ("Lockdown Mode (Kill Switch)", app.toggles.lockdown),
        ("Local Network Sharing (LAN)", app.toggles.lan),
        ("Quantum-resistant Tunnel", app.toggles.quantum_resistant),
        ("DAITA (Anti-AI Traffic Analysis)", app.toggles.daita),
        ("Multihop (Entry -> Exit)", app.toggles.multihop),
        ("DNS Blockers (Ads / Trackers / Malware)", app.toggles.dns_block_ads),
        ("Auto-connect on Boot", app.toggles.auto_connect),
        ("In-tunnel IPv6 (Dual-Stack)", app.toggles.ipv6),
    ];

    let items: Vec<ListItem> = entries
        .iter()
        .map(|(label, state)| {
            let (badge, color) = if *state {
                ("[ ON  ]", STATUS_GREEN)
            } else {
                ("[ OFF ]", STATUS_RED)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", badge),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*label, Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Параметры Mullvad [Enter: переключить] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
        )
        .highlight_style(
            Style::default()
                .bg(MULLVAD_BLUE_MID)
                .fg(MULLVAD_YELLOW)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, area, &mut app.toggle_list_state);
}

fn draw_logs(f: &mut Frame, app: &AppState, area: Rect) {
    let visible_lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(4)
        .rev()
        .map(|l| Line::from(Span::styled(l.as_str(), Style::default().fg(Color::Gray))))
        .collect();

    let block = Paragraph::new(visible_lines).block(
        Block::default()
            .title(" Журнал событий & Watchdog ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
    );
    f.render_widget(block, area);
}

fn draw_footer(f: &mut Frame, app: &AppState, area: Rect) {
    let text = match &app.input_mode {
        InputMode::AddKeyNumber => format!(
            " Введите 16-значный номер аккаунта: {}_ (Enter — далее, Esc — отмена)",
            app.input_buffer
        ),
        InputMode::AddKeyLabel(_) => format!(
            " Введите метку (алиас) аккаунта: {}_ (Enter — сохранить)",
            app.input_buffer
        ),
        InputMode::Normal => {
            " [c] Auto-Connect/Evict  [d] Disconnect  [r] Reconnect  [w] Auto-Intercept  [Tab] Вкладки  [q] Выход".to_string()
        }
    };
    let bar = Paragraph::new(text).style(
        Style::default()
            .fg(MULLVAD_BLUE_DARK)
            .bg(MULLVAD_YELLOW)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(bar, area);
}

fn draw_onboarding(f: &mut Frame, app: &AppState) {
    let ob = &app.onboarding;
    let area = centered_rect(76, 23, f.area());

    let outer = Block::default()
        .title(" MULLVAD MULTI-ACCOUNT CLI — МАСТЕР ПЕРВОГО ЗАПУСКА ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MULLVAD_YELLOW))
        .style(Style::default().bg(MULLVAD_BLUE_DARK));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(7),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(
            "Добавьте 1 или несколько 16-значных ключей Mullvad (Enter — добавить ключ, Tab — поля, F5 — старт):",
        )
        .style(Style::default().fg(Color::White)),
        rows[0],
    );

    let key_border = if ob.field == OnboardingField::KeyInput {
        Style::default().fg(MULLVAD_YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MULLVAD_BLUE_MID)
    };
    f.render_widget(
        Paragraph::new(format!(" {}_", ob.key_buf)).block(
            Block::default()
                .title(" 16-значный номер аккаунта Mullvad ")
                .borders(Borders::ALL)
                .border_style(key_border),
        ),
        rows[1],
    );

    let lbl_border = if ob.field == OnboardingField::LabelInput {
        Style::default().fg(MULLVAD_YELLOW).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MULLVAD_BLUE_MID)
    };
    f.render_widget(
        Paragraph::new(format!(" {}_", ob.label_buf)).block(
            Block::default()
                .title(" Метка / Алиас (необязательно, например: Acc #1 - Main) ")
                .borders(Borders::ALL)
                .border_style(lbl_border),
        ),
        rows[2],
    );

    let pool_info = if app.config.accounts.is_empty() {
        "Пул ключей: пусто (введите ключ и нажмите Enter)".to_string()
    } else {
        let list: Vec<String> = app
            .config
            .accounts
            .iter()
            .map(|a| format!("{} ({})", a.label, AppConfig::mask_key(&a.key)))
            .collect();
        format!("В пуле ({}): {}", app.config.accounts.len(), list.join(" | "))
    };
    f.render_widget(
        Paragraph::new(pool_info).style(Style::default().fg(STATUS_GREEN)),
        rows[3],
    );

    let toggles = [
        (OnboardingField::ToggleLockdown, "Lockdown Mode (Kill Switch)", ob.lockdown),
        (OnboardingField::ToggleQuantum, "Quantum-resistant Tunnel", ob.quantum),
        (OnboardingField::ToggleDns, "DNS Content Blockers (Ads / Trackers / Malware)", ob.dns_block),
        (OnboardingField::ToggleAutoConnect, "Auto-connect при загрузке системы", ob.auto_connect),
        (OnboardingField::ToggleAutoIntercept, "Auto-Intercept & Slot Eviction (защита профиля)", ob.auto_intercept),
    ];

    let lines: Vec<Line> = toggles
        .iter()
        .map(|(fld, title, state)| {
            let selected = ob.field == *fld;
            let prefix = if selected { "▶ " } else { "  " };
            let badge = if *state { "[ON] " } else { "[OFF]" };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(MULLVAD_YELLOW)),
                Span::styled(
                    badge,
                    Style::default()
                        .fg(if *state { STATUS_GREEN } else { STATUS_RED })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {}", title),
                    Style::default().fg(if selected { MULLVAD_YELLOW } else { Color::White }),
                ),
            ])
        })
        .collect();

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(" Стартовые настройки безопасности (Пробел / Enter — переключить) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MULLVAD_BLUE_MID)),
        ),
        rows[4],
    );

    if let Some(ref msg) = ob.notice {
        f.render_widget(
            Paragraph::new(msg.as_str()).style(Style::default().fg(STATUS_WARN)),
            rows[5],
        );
    }

    let finish_style = if ob.field == OnboardingField::FinishButton {
        Style::default()
            .fg(MULLVAD_BLUE_DARK)
            .bg(MULLVAD_YELLOW)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MULLVAD_YELLOW).add_modifier(Modifier::BOLD)
    };
    f.render_widget(
        Paragraph::new(" [ F5 / Enter здесь: Сохранить настройки и запустить TUI ] ")
            .style(finish_style),
        rows[6],
    );
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height.min(r.height)),
            Constraint::Fill(1),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}
