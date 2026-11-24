mod config;
mod mullvad;
mod ping;
mod ui;
mod watchdog;

use anyhow::Result;
use clap::Parser;
use config::AppConfig;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "mullvad-cli",
    version,
    about = "Mullvad Multi-Account CLI, Multihop Intercept Watchdog & TUI"
)]
struct Cli {
    /// Запустить в фоновом режиме автовосстановления и перехвата профиля
    #[arg(long, alias = "daemon")]
    watch: bool,

    /// Выполнить однократное автоподключение (с поиском или выбиванием слота) и выйти
    #[arg(long)]
    auto: bool,

    /// Показать текущий статус соединения, маршрута и аккаунта
    #[arg(long)]
    status: bool,

    /// Замерить задержку до ВСЕХ серверов Mullvad и вывести рейтинг
    #[arg(long)]
    ping: bool,

    /// Выборочно проверить пинг связки Вход -> Выход без разрыва соединения (2 аргумента: ENTRY EXIT)
    #[arg(long, num_args = 2, value_names = ["ENTRY", "EXIT"])]
    test_route: Option<Vec<String>>,

    /// Добавить новый 16-значный ключ Mullvad в пул
    #[arg(long, value_name = "ACCOUNT_NUMBER")]
    add_key: Option<String>,

    /// Метка для добавляемого ключа
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,

    /// Задать входной узел (Hop 1) для Multihop (например: "se sto" или "se-sto-wg-001")
    #[arg(long, value_name = "ENTRY")]
    entry: Option<String>,

    /// Задать выходной узел (Hop 2) (например: "ch zrh" или "ch-zrh-wg-001")
    #[arg(long, value_name = "EXIT")]
    exit: Option<String>,

    /// Переключиться в режим одного сервера (1-HOP), отключив Multihop
    #[arg(long)]
    single: bool,

    /// Включить или выключить принудительный авто-перехват настроек (true/false)
    #[arg(long)]
    intercept: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = AppConfig::load()?;

    if let Some(key) = cli.add_key {
        let label = cli
            .label
            .unwrap_or_else(|| format!("Acc #{}", cfg.accounts.len() + 1));
        cfg.add_account(label.clone(), &key)?;
        println!(
            "Аккаунт '{}' ({}) сохранён в {:?}",
            label,
            AppConfig::mask_key(&key),
            AppConfig::config_path()?
        );
        return Ok(());
    }

    let mut profile_changed = false;
    if cli.single {
        mullvad::set_multihop(false).await?;
        cfg.profile.entry_relay = None;
        cfg.profile.multihop = Some(false);
        profile_changed = true;
        println!("Режим одного сервера (1-HOP) активирован.");
    }
    if let Some(entry) = cli.entry {
        mullvad::set_entry_location(&entry).await?;
        cfg.profile.entry_relay = Some(entry.clone());
        cfg.profile.multihop = Some(true);
        cfg.profile.enforce_settings = true;
        profile_changed = true;
        println!("Entry-сервер (Hop 1) установлен и зафиксирован: {}", entry);
    }
    if let Some(exit) = cli.exit {
        mullvad::set_exit_location(&exit).await?;
        cfg.profile.exit_relay = Some(exit.clone());
        cfg.profile.enforce_settings = true;
        profile_changed = true;
        println!("Exit-сервер (Hop 2) установлен и зафиксирован: {}", exit);
    }
    if let Some(en) = cli.intercept {
        cfg.profile.enforce_settings = en;
        profile_changed = true;
        println!("Режим авто-перехвата настроек: {}", if en { "ON" } else { "OFF" });
    }
    if profile_changed {
        cfg.save()?;
        if !cli.watch && !cli.auto && !cli.status {
            return Ok(());
        }
    }

    if cli.status {
        let st = mullvad::get_status().await?;
        let acc = mullvad::account_get().await?;
        let tog = mullvad::fetch_toggles().await;
        println!("State:     {:?}", st.state);
        println!(
            "Account:   {}",
            acc.account_number
                .as_deref()
                .map(AppConfig::mask_key)
                .unwrap_or_else(|| "None".into())
        );
        println!("Device:    {}", acc.device_name.unwrap_or_else(|| "-".into()));
        println!("Multihop:  {}", if tog.multihop { "ON" } else { "OFF" });
        println!("Entry:     {}", tog.entry_relay.unwrap_or_else(|| "-".into()));
        println!("Exit:      {}", st.relay.unwrap_or_else(|| "-".into()));
        println!("Location:  {}", st.location.unwrap_or_else(|| "-".into()));
        let total_rtt = ping::measure_active_tunnel_rtt().await;
        println!("IPv4:      {}", st.ipv4.unwrap_or_else(|| "-".into()));
        println!("TotalPing: {} ({})", total_rtt.map(|m| format!("{} ms", m)).unwrap_or_else(|| "DEAD/TIMEOUT".into()), if tog.multihop { "2-HOP" } else { "1-HOP" });
        println!("Intercept: {}", if cfg.profile.enforce_settings { "LOCKED" } else { "FREE" });
        return Ok(());
    }

    if let Some(pair) = cli.test_route {
        let relays = mullvad::fetch_relays(usize::MAX).await?;
        let res = ping::check_entry_exit_pair(&relays, &pair[0], &pair[1]).await;
        println!(
            "Вход  (Hop 1): {:<34} -> {} ms",
            res.entry_label,
            res.entry_ms.map(|m| m.to_string()).unwrap_or_else(|| "--".into())
        );
        println!(
            "Выход (Hop 2): {:<34} -> {} ms",
            res.exit_label,
            res.exit_ms.map(|m| m.to_string()).unwrap_or_else(|| "--".into())
        );
        return Ok(());
    }

    if cli.ping {
        let relays = mullvad::fetch_relays(usize::MAX).await?;
        println!("Замер задержки до всех {} серверов Mullvad...", relays.len());
        let ranked = ping::benchmark_relays(relays).await;
        for r in ranked.into_iter().filter(|r| r.latency_ms.is_some()).take(25) {
            println!(
                "{:<16} {:<16} {:<18} {:>4} ms",
                r.country_name,
                r.city_name,
                r.hostname,
                r.latency_ms.unwrap()
            );
        }
        return Ok(());
    }

    if cli.auto {
        watchdog::ensure_connected(&mut cfg, &None, true).await?;
        return Ok(());
    }

    if cli.watch {
        println!(
            "Запуск Mullvad Watchdog (интервал: {}с, аккаунтов в пуле: {}, перехват: {})...",
            cfg.check_interval_secs,
            cfg.accounts.len(),
            cfg.profile.enforce_settings
        );
        loop {
            // Перечитываем конфиг на каждой итерации, чтобы подхватывать изменения из CLI/TUI
            if let Ok(fresh) = AppConfig::load() {
                cfg = fresh;
            }
            if let Err(e) = watchdog::ensure_connected(&mut cfg, &None, false).await {
                eprintln!("[WATCHDOG ERROR] {}", e);
            }
            tokio::time::sleep(Duration::from_secs(cfg.check_interval_secs)).await;
        }
    }

    ui::run_tui(cfg).await
}
