use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    pub label: String,
    pub key: String,
    #[serde(default)]
    pub last_used_ts: i64,
    #[serde(default)]
    pub kick_timestamps: Vec<i64>,
    #[serde(default)]
    pub cooldown_until: i64,
    #[serde(default)]
    pub cached_devices: Option<usize>,
    #[serde(default)]
    pub devices_checked_ts: i64,
    #[serde(default)]
    pub expires_at_raw: Option<String>,
    #[serde(default)]
    pub expiry_checked_ts: i64,
}

impl AccountEntry {
    pub fn days_remaining(&self) -> Option<i64> {
        let raw = self.expires_at_raw.as_deref()?;
        // Формат Mullvad: "2026-12-13 02:01:43 +01:00"
        if let Ok(dt) = DateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S %z") {
            let secs = dt.with_timezone(&Utc).signed_duration_since(Utc::now()).num_seconds();
            return Some((secs / 86400).max(0));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvictionPolicy {
    RoundRobin,
    OldestDevice,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self::RoundRobin
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnforcedProfile {
    #[serde(default)]
    pub enforce_settings: bool,
    pub entry_relay: Option<String>,
    pub exit_relay: Option<String>,
    pub multihop: Option<bool>,
    pub lockdown: Option<bool>,
    pub quantum_resistant: Option<bool>,
    pub daita: Option<bool>,
    pub ipv6: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub accounts: Vec<AccountEntry>,
    #[serde(default)]
    pub whitelist_devices: Vec<String>,
    #[serde(default)]
    pub eviction_policy: EvictionPolicy,
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
    #[serde(default)]
    pub rr_index: usize,
    #[serde(default)]
    pub profile: EnforcedProfile,
}

fn default_check_interval() -> u64 {
    3
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
            whitelist_devices: Vec::new(),
            eviction_policy: EvictionPolicy::RoundRobin,
            check_interval_secs: 3,
            rr_index: 0,
            profile: EnforcedProfile::default(),
        }
    }
}

/// Межпроцессная блокировка (systemd daemon <-> TUI) для исключения гонок вызовов mullvad CLI
pub struct ProcessLock {
    file: File,
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl AppConfig {
    pub fn config_path() -> Result<PathBuf> {
        let base = dirs::config_dir().context("Не удалось определить ~/.config")?;
        Ok(base.join("mullvad-cli").join("config.toml"))
    }

    pub fn try_acquire_lock() -> Option<ProcessLock> {
        let path = Self::config_path().ok()?.with_extension("lock");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .ok()?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Some(ProcessLock { file })
        } else {
            None
        }
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            let cfg = Self::default();
            cfg.save()?;
            return Ok(cfg);
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("Ошибка чтения конфигурации: {}", path.display()))?;
        let cfg: AppConfig = toml::from_str(&raw).context("Ошибка парсинга config.toml")?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("toml.tmp");
        let serialized = toml::to_string_pretty(self)?;
        fs::write(&tmp_path, serialized)?;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    pub fn add_account(&mut self, label: String, raw_key: &str) -> Result<()> {
        let clean_key: String = raw_key.chars().filter(|c| c.is_ascii_digit()).collect();
        if clean_key.len() != 16 {
            anyhow::bail!("Ключ Mullvad должен содержать ровно 16 цифр");
        }
        if self.accounts.iter().any(|a| a.key == clean_key) {
            anyhow::bail!("Этот аккаунт уже добавлен в пул");
        }
        self.accounts.push(AccountEntry {
            label,
            key: clean_key,
            last_used_ts: 0,
            kick_timestamps: Vec::new(),
            cooldown_until: 0,
            cached_devices: None,
            devices_checked_ts: 0,
            expires_at_raw: None,
            expiry_checked_ts: 0,
        });
        self.save()
    }

    pub fn mask_key(key: &str) -> String {
        if key.len() == 16 {
            format!("{} •••• •••• {}", &key[0..4], &key[12..16])
        } else {
            "•••• •••• •••• ••••".to_string()
        }
    }
}
