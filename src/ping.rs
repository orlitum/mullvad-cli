use crate::mullvad::RelayNode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

pub async fn measure_tcp_latency(ip: &str, port: u16, timeout_ms: u64) -> Option<u64> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
    let start = Instant::now();
    match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(start.elapsed().as_millis() as u64)
        }
        _ => None,
    }
}

pub async fn benchmark_relays(mut relays: Vec<RelayNode>) -> Vec<RelayNode> {
    let sem = Arc::new(Semaphore::new(64));
    let mut handles = Vec::with_capacity(relays.len());

    for mut relay in relays.drain(..) {
        let permit = sem.clone().acquire_owned().await.unwrap();
        handles.push(tokio::spawn(async move {
            let lat = measure_tcp_latency(&relay.ipv4, 443, 750).await;
            relay.latency_ms = lat;
            drop(permit);
            relay
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }

    results.sort_by_key(|r| r.latency_ms.unwrap_or(u64::MAX));
    results
}

pub struct RouteCheckResult {
    pub entry_label: String,
    pub exit_label: String,
    pub entry_ms: Option<u64>,
    pub exit_ms: Option<u64>,
}

/// Выборочная проверка задержки до выбранных входного и выходного узлов без разрыва туннеля
pub async fn check_entry_exit_pair(
    relays: &[RelayNode],
    entry_spec: &str,
    exit_spec: &str,
) -> RouteCheckResult {
    let find_node = |spec: &str| -> Option<&RelayNode> {
        let tokens: Vec<&str> = spec.split_whitespace().collect();
        if let Some(last) = tokens.last() {
            if let Some(exact) = relays.iter().find(|r| r.hostname.eq_ignore_ascii_case(last)) {
                return Some(exact);
            }
        }
        if tokens.len() >= 2 {
            if let Some(city) = relays.iter().find(|r| {
                r.country_code.eq_ignore_ascii_case(tokens[0])
                    && r.city_code.eq_ignore_ascii_case(tokens[1])
            }) {
                return Some(city);
            }
        }
        if let Some(first) = tokens.first() {
            return relays
                .iter()
                .find(|r| r.country_code.eq_ignore_ascii_case(first) || r.hostname.contains(first));
        }
        None
    };

    let entry_node = find_node(entry_spec);
    let exit_node = find_node(exit_spec);

    let entry_ms = match entry_node {
        Some(n) => measure_tcp_latency(&n.ipv4, 443, 800).await,
        None => None,
    };
    let exit_ms = match exit_node {
        Some(n) => measure_tcp_latency(&n.ipv4, 443, 800).await,
        None => None,
    };

    let entry_label = entry_node
        .map(|n| format!("{} ({}, {})", n.hostname, n.country_name, n.city_name))
        .unwrap_or_else(|| entry_spec.to_string());
    let exit_label = exit_node
        .map(|n| format!("{} ({}, {})", n.hostname, n.country_name, n.city_name))
        .unwrap_or_else(|| exit_spec.to_string());

    RouteCheckResult {
        entry_label,
        exit_label,
        entry_ms,
        exit_ms,
    }
}

/// Замер реального сквозного пинга активного туннеля (учитывает оба прыжка Multihop)
pub async fn measure_active_tunnel_rtt() -> Option<u64> {
    if let Some(ms) = measure_tcp_latency("10.64.0.1", 53, 800).await {
        return Some(ms);
    }
    measure_tcp_latency("1.1.1.1", 53, 900).await
}
