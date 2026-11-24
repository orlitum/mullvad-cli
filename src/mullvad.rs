use anyhow::{Context, Result};
use regex::Regex;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnState {
    Connected,
    Connecting,
    Disconnected,
    Blocked(String),
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct ConnectionStatus {
    pub state: VpnState,
    pub relay: Option<String>,
    pub location: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub account_number: Option<String>,
    pub device_name: Option<String>,
    pub expires_at: Option<String>,
    pub is_expired: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub name: String,
    pub is_current: bool,
}

#[derive(Debug, Clone)]
pub struct RelayNode {
    pub country_code: String,
    pub country_name: String,
    pub city_code: String,
    pub city_name: String,
    pub hostname: String,
    pub ipv4: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct MullvadToggles {
    pub lockdown: bool,
    pub lan: bool,
    pub quantum_resistant: bool,
    pub daita: bool,
    pub ipv6: bool,
    pub multihop: bool,
    pub auto_connect: bool,
    pub dns_block_ads: bool,
    pub entry_relay: Option<String>,
    pub exit_relay: Option<String>,
}

async fn run_mullvad(args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new("mullvad")
        .args(args)
        .output()
        .await
        .with_context(|| format!("Не удалось запустить mullvad {:?}", args))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    Ok((out.status.success(), stdout, stderr))
}

pub async fn get_status() -> Result<ConnectionStatus> {
    let (_, stdout, _) = run_mullvad(&["status", "-v"]).await?;

    let state = if stdout.contains("Connected") && !stdout.contains("Disconnected") {
        VpnState::Connected
    } else if stdout.contains("Connecting") {
        VpnState::Connecting
    } else if stdout.contains("Disconnected") {
        VpnState::Disconnected
    } else if stdout.contains("Blocked") {
        VpnState::Blocked(stdout.lines().next().unwrap_or("Blocked").to_string())
    } else {
        VpnState::Unknown(stdout.lines().next().unwrap_or("Unknown").to_string())
    };

    let relay_re = Regex::new(r"Relay:\s*([^\n]+)").unwrap();
    let loc_re = Regex::new(r"Visible location:\s*(.+)").unwrap();
    let ip_re = Regex::new(r"IPv4:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();
    let ip6_re = Regex::new(r"IPv6:\s*([0-9a-fA-F:]+)").unwrap();

    Ok(ConnectionStatus {
        state,
        relay: relay_re.captures(&stdout).map(|c| c[1].trim().to_string()),
        location: loc_re.captures(&stdout).map(|c| {
            let raw = c[1].trim();
            raw.split(". IPv4:").next().unwrap_or(raw).trim().to_string()
        }),
        ipv4: ip_re.captures(&stdout).map(|c| c[1].to_string()),
        ipv6: ip6_re.captures(&stdout).map(|c| c[1].to_string()),
    })
}

pub async fn account_get() -> Result<AccountInfo> {
    let (ok, stdout, stderr) = run_mullvad(&["account", "get"]).await?;
    let text = format!("{}\n{}", stdout, stderr);
    if !ok || text.contains("Not logged in") {
        return Ok(AccountInfo {
            account_number: None,
            device_name: None,
            expires_at: None,
            is_expired: false,
        });
    }

    let acc_re = Regex::new(r"Mullvad account:\s*([0-9]+)").unwrap();
    let dev_re = Regex::new(r"Device name:\s*(.+)").unwrap();
    let exp_re = Regex::new(r"Expires at:\s*(.+)").unwrap();

    let account_number = acc_re.captures(&text).map(|c| c[1].trim().to_string());
    let device_name = dev_re.captures(&text).map(|c| c[1].trim().to_string());
    let expires_at = exp_re.captures(&text).map(|c| c[1].trim().to_string());
    let is_expired = text.to_lowercase().contains("expired")
        || text.to_lowercase().contains("out of time");

    Ok(AccountInfo {
        account_number,
        device_name,
        expires_at,
        is_expired,
    })
}

pub async fn account_login(key: &str) -> Result<Result<(), String>> {
    let (ok, stdout, stderr) = run_mullvad(&["account", "login", key]).await?;
    let combined = format!("{}\n{}", stdout, stderr);
    if ok
        && !combined.to_lowercase().contains("error")
        && !combined.to_lowercase().contains("too many devices")
    {
        Ok(Ok(()))
    } else {
        Ok(Err(combined.trim().to_string()))
    }
}

pub async fn list_devices(key: Option<&str>) -> Result<Vec<DeviceEntry>> {
    let args = match key {
        Some(k) => vec!["account", "list-devices", "--account", k],
        None => vec!["account", "list-devices"],
    };
    let (ok, stdout, stderr) = run_mullvad(&args).await?;
    if !ok {
        anyhow::bail!("Ошибка list-devices: {} {}", stdout.trim(), stderr.trim());
    }

    let current_dev = account_get().await.ok().and_then(|i| i.device_name);
    let mut devices = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Devices on")
            || trimmed.starts_with("---")
            || trimmed.starts_with("Name")
        {
            continue;
        }
        let is_current_tag = trimmed.contains("(current)");
        let clean = trimmed.split('(').next().unwrap_or(trimmed).trim();
        let tokens: Vec<&str> = clean.split_whitespace().collect();
        let name = if tokens.len() >= 2 && !tokens[1].contains(':') {
            format!("{} {}", tokens[0], tokens[1])
        } else if !tokens.is_empty() {
            tokens[0].to_string()
        } else {
            continue;
        };

        let is_current = is_current_tag
            || current_dev
                .as_deref()
                .map(|c| c.eq_ignore_ascii_case(&name))
                .unwrap_or(false);

        devices.push(DeviceEntry { name, is_current });
    }
    Ok(devices)
}

pub async fn revoke_device(device_name: &str, key: Option<&str>) -> Result<()> {
    let mut args = vec!["account", "revoke-device", device_name];
    if let Some(k) = key {
        args.extend_from_slice(&["--account", k]);
    }
    let (ok, stdout, stderr) = run_mullvad(&args).await?;
    if !ok {
        anyhow::bail!(
            "Ошибка отзыва устройства '{}': {} {}",
            device_name,
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(())
}

pub async fn connect() -> Result<()> {
    let _ = run_mullvad(&["connect"]).await?;
    Ok(())
}

pub async fn disconnect() -> Result<()> {
    let _ = run_mullvad(&["disconnect"]).await?;
    Ok(())
}

pub async fn reconnect() -> Result<()> {
    let _ = run_mullvad(&["reconnect"]).await?;
    Ok(())
}

pub async fn set_exit_location(spec: &str) -> Result<()> {
    let parts: Vec<&str> = spec.split_whitespace().collect();
    let mut args = vec!["relay", "set", "location"];
    args.extend(parts);
    let _ = run_mullvad(&args).await?;
    Ok(())
}

pub async fn set_entry_location(spec: &str) -> Result<()> {
    let parts: Vec<&str> = spec.split_whitespace().collect();
    let mut args = vec!["relay", "set", "entry-location"];
    args.extend(parts);
    let (ok, _, _) = run_mullvad(&args).await?;
    if !ok {
        let mut fallback = vec!["relay", "set", "tunnel", "wireguard", "--entry-location"];
        fallback.extend(spec.split_whitespace());
        let _ = run_mullvad(&fallback).await?;
    }
    let _ = run_mullvad(&["relay", "set", "multihop", "on"]).await?;
    Ok(())
}

pub async fn set_multihop(enable: bool) -> Result<()> {
    let state = if enable { "on" } else { "off" };
    let _ = run_mullvad(&["relay", "set", "multihop", state]).await?;
    Ok(())
}

pub async fn fetch_toggles() -> MullvadToggles {
    let mut t = MullvadToggles::default();

    if let Ok((_, out, _)) = run_mullvad(&["lockdown-mode", "get"]).await {
        t.lockdown = out.to_lowercase().contains("on");
    }
    if let Ok((_, out, _)) = run_mullvad(&["lan", "get"]).await {
        t.lan = out.to_lowercase().contains("allow");
    }
    if let Ok((_, out, _)) = run_mullvad(&["auto-connect", "get"]).await {
        t.auto_connect = out.to_lowercase().contains("on");
    }
    if let Ok((_, out, _)) = run_mullvad(&["tunnel", "get"]).await {
        let low = out.to_lowercase();
        t.quantum_resistant = low.contains("quantum-resistant tunnel: on") || low.contains("quantum-resistant: on");
        t.daita = low.contains("daita: on");
        t.ipv6 = low.contains("ipv6: on") || low.contains("in-tunnel ipv6: on");
    }
    if let Ok((_, out, _)) = run_mullvad(&["relay", "get"]).await {
        let low = out.to_lowercase();
        t.multihop = low.contains("multihop state: enabled")
            || low.contains("multihop: enabled")
            || low.contains("multihop: on");
        for line in out.lines() {
            let trimmed = line.trim();
            let low_line = trimmed.to_lowercase();
            if low_line.starts_with("multihop entry:") || low_line.starts_with("entry") {
                t.entry_relay = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
            } else if low_line.starts_with("location:") || low_line.starts_with("exit") {
                t.exit_relay = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    if let Ok((_, out, _)) = run_mullvad(&["dns", "get"]).await {
        let low = out.to_lowercase();
        t.dns_block_ads = low.contains("block ads: true") || low.contains("ads: true");
    }

    t
}

pub async fn apply_toggle(name: &str, enable: bool) -> Result<()> {
    let state_on_off = if enable { "on" } else { "off" };
    match name {
        "lockdown" => {
            run_mullvad(&["lockdown-mode", "set", state_on_off]).await?;
        }
        "lan" => {
            let v = if enable { "allow" } else { "block" };
            run_mullvad(&["lan", "set", v]).await?;
        }
        "quantum" => {
            run_mullvad(&["tunnel", "set", "wireguard", "--quantum-resistant", state_on_off]).await?;
        }
        "daita" => {
            run_mullvad(&["tunnel", "set", "wireguard", "--daita", state_on_off]).await?;
        }
        "ipv6" => {
            run_mullvad(&["tunnel", "set", "ipv6", state_on_off]).await?;
        }
        "multihop" => {
            run_mullvad(&["relay", "set", "multihop", state_on_off]).await?;
        }
        "auto_connect" => {
            run_mullvad(&["auto-connect", "set", state_on_off]).await?;
        }
        "dns_ads" => {
            let mut args = vec!["dns", "set", "default"];
            if enable {
                args.extend_from_slice(&["--block-ads", "--block-trackers", "--block-malware"]);
            }
            run_mullvad(&args).await?;
        }
        _ => {}
    }
    Ok(())
}

pub async fn fetch_relays(limit_per_city: usize) -> Result<Vec<RelayNode>> {
    let (_, stdout, _) = run_mullvad(&["relay", "list"]).await?;
    let mut relays = Vec::new();

    let country_re = Regex::new(r"^([A-Za-z\s]+)\s+\(([a-z]{2})\)$").unwrap();
    let city_re = Regex::new(r"^\s+([A-Za-z\s\-]+)\s+\(([a-z]{3})\)\s+@").unwrap();
    let srv_re = Regex::new(r"^\s+([a-z]{2}-[a-z]{3}-wg-[0-9]+)\s+\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();

    let mut cur_country = String::new();
    let mut cur_cc = String::new();
    let mut cur_city = String::new();
    let mut cur_city_code = String::new();
    let mut city_count = 0;

    for line in stdout.lines() {
        if let Some(c) = country_re.captures(line) {
            cur_country = c[1].trim().to_string();
            cur_cc = c[2].to_string();
        } else if let Some(c) = city_re.captures(line) {
            cur_city = c[1].trim().to_string();
            cur_city_code = c[2].to_string();
            city_count = 0;
        } else if let Some(c) = srv_re.captures(line) {
            if city_count < limit_per_city {
                relays.push(RelayNode {
                    country_code: cur_cc.clone(),
                    country_name: cur_country.clone(),
                    city_code: cur_city_code.clone(),
                    city_name: cur_city.clone(),
                    hostname: c[1].to_string(),
                    ipv4: c[2].to_string(),
                    latency_ms: None,
                });
                city_count += 1;
            }
        }
    }
    Ok(relays)
}
