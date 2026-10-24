use crate::credentials::load_credentials;
use crate::exploits::run_pedrib_exploits;
use crate::filter::{check_filters, parse_filter_rules};
use crate::http_client::{
    basic_auth_header, detect_device, http_get, probe_hnap, tcp_connect, try_basic_auth,
    HttpResponse,
};
use crate::models::{Config, FilterRule, ScanResult};
use crossbeam_channel::{Receiver, Sender};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum ScanMsg {
    Result(Box<ScanResult>),
    Stats(ScanStats),
    Done,
    Error(String),
}

#[derive(Default, Clone, Debug)]
pub struct ScanStats {
    pub active_connect: u64,
    pub active_process: u64,
    pub queued: u64,
    pub completed: u64,
    pub total: u64,
    pub found: u64,
    pub failed: u64,
    pub elapsed_secs: u64,
}

pub fn start_scan(
    config: Arc<Config>,
    stop_flag: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
) -> Receiver<ScanMsg> {
    let (tx, rx) = crossbeam_channel::unbounded();
    std::thread::spawn(move || {
        // Range expansion also runs off the UI thread.
        let targets = match expand_targets(&config) {
            Ok(targets) => targets,
            Err(error) => {
                let _ = tx.send(ScanMsg::Error(error));
                return;
            }
        };
        scan_coordinator(config, targets, stop_flag, pause_flag, tx);
    });
    rx
}

fn expand_targets(config: &Config) -> Result<Vec<(Ipv4Addr, u16)>, String> {
    let ips = crate::ip_range::parse_all_ranges_checked(&config.ranges.join("\n"))?;
    if config.ports.is_empty() || config.ports.contains(&0) {
        return Err("Add valid scan ports from 1 to 65535.".into());
    }
    let mut targets = Vec::with_capacity(ips.len().saturating_mul(config.ports.len()));
    for ip in ips {
        for &port in &config.ports {
            targets.push((ip, port));
        }
    }
    targets.sort_unstable();
    targets.dedup();
    Ok(targets)
}

#[derive(Default)]
struct Counters {
    connect: AtomicU64,
    process: AtomicU64,
    completed: AtomicU64,
    found: AtomicU64,
    failed: AtomicU64,
}
impl Counters {
    fn snapshot(&self, total: u64, queued: u64, start: Instant) -> ScanStats {
        ScanStats {
            active_connect: self.connect.load(Ordering::Relaxed),
            active_process: self.process.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            found: self.found.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            total,
            queued,
            elapsed_secs: start.elapsed().as_secs(),
        }
    }
}
struct ActiveGuard<'a>(&'a AtomicU64);
impl<'a> ActiveGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn scan_coordinator(
    config: Arc<Config>,
    targets: Vec<(Ipv4Addr, u16)>,
    stop: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    tx: Sender<ScanMsg>,
) {
    let total = targets.len() as u64;
    let start = Instant::now();
    let (work_tx, work_rx) = crossbeam_channel::unbounded();
    for target in targets {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if work_tx.send(target).is_err() {
            break;
        }
    }
    drop(work_tx);
    let basic_pairs = Arc::new(load_credentials(&config.auth_basic_file));
    let filter_rules = Arc::new(load_filter_rules());
    let counters = Arc::new(Counters::default());
    let finished = Arc::new(AtomicBool::new(false));
    let stats_thread = {
        let (tx, counters, finished, work_rx) = (
            tx.clone(),
            counters.clone(),
            finished.clone(),
            work_rx.clone(),
        );
        std::thread::spawn(move || {
            while !finished.load(Ordering::Acquire) {
                if tx
                    .send(ScanMsg::Stats(counters.snapshot(
                        total,
                        work_rx.len() as u64,
                        start,
                    )))
                    .is_err()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let mut workers = Vec::new();
    for _ in 0..(config.threads.clamp(1, 1000) as usize).min(total as usize) {
        let (config, work_rx, stop, pause, tx, counters, basic_pairs, filter_rules) = (
            config.clone(),
            work_rx.clone(),
            stop.clone(),
            pause.clone(),
            tx.clone(),
            counters.clone(),
            basic_pairs.clone(),
            filter_rules.clone(),
        );
        workers.push(std::thread::spawn(move || {
            while let Ok((ip, port)) = work_rx.recv() {
                while pause.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                apply_scan_delay(config.scan_mode);
                let result = process_target(
                    (ip, port),
                    &config,
                    &basic_pairs,
                    &filter_rules,
                    &counters,
                    &stop,
                    &|r| {
                        let _ = tx.send(ScanMsg::Result(Box::new(r)));
                    },
                );
                if result.tcp_open {
                    counters.found.fetch_add(1, Ordering::Relaxed);
                }
                if matches!(
                    result.status.as_str(),
                    "Closed"
                        | "Timed out"
                        | "Can't connect"
                        | "Can't load"
                        | "TLS error"
                        | "Auth failed"
                ) {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                }
                if tx.send(ScanMsg::Result(Box::new(result))).is_err() {
                    break;
                }
                counters.completed.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    // Stop and join the ticker before Done: no stale statistics can arrive afterward.
    finished.store(true, Ordering::Release);
    let _ = stats_thread.join();
    let _ = tx.send(ScanMsg::Stats(counters.snapshot(total, 0, start)));
    let _ = tx.send(ScanMsg::Done);
}

fn update_metadata(result: &mut ScanResult, response: &HttpResponse) {
    if !response.server.is_empty() {
        result.server_name = response.server.clone();
    }
    if !response.realm.is_empty() {
        result.realm = response.realm.clone();
    }
    let detected = detect_device(&result.server_name, &result.realm, &response.body);
    if !detected.is_empty() {
        result.device_type = detected;
    }
    result.http_status = response.status;
    result.info = format!("HTTP {} — {}", response.status, response.url);
    if !response.location.is_empty() {
        result
            .info
            .push_str(&format!("; redirects to {}", response.location));
    }
}

fn interrupted(
    result: &mut ScanResult,
    stop: &AtomicBool,
    start: Instant,
    deadline: Duration,
) -> bool {
    if stop.load(Ordering::Relaxed) {
        result.status = "Stopped".into();
        result.info = "Scan stopped by user".into();
        true
    } else if start.elapsed() >= deadline {
        result.status = "Timed out".into();
        result.info = "Per-target processing deadline exceeded".into();
        true
    } else {
        false
    }
}

fn process_target(
    (ip, port): (Ipv4Addr, u16),
    config: &Config,
    basic_pairs: &[(String, String)],
    filter_rules: &[FilterRule],
    counters: &Counters,
    stop: &AtomicBool,
    publish: &dyn Fn(ScanResult),
) -> ScanResult {
    let start = Instant::now();
    let deadline = Duration::from_secs(config.thread_timeout_min.max(1) as u64 * 60);
    let mut result = ScanResult {
        ip: ip.to_string(),
        port,
        status: "Connecting".into(),
        ..Default::default()
    };
    publish(result.clone());
    {
        let _connecting = ActiveGuard::new(&counters.connect);
        match tcp_connect(ip, port, config.connect_timeout_ms) {
            Ok(stream) => {
                drop(stream);
                result.tcp_open = true;
            }
            Err(error) => {
                result.status = match error.kind() {
                    ErrorKind::ConnectionRefused => "Closed",
                    ErrorKind::TimedOut | ErrorKind::WouldBlock => "Timed out",
                    _ => "Can't connect",
                }
                .into();
                result.info = error.to_string();
                result.latency_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        }
    }
    result.latency_ms = start.elapsed().as_millis() as u64;
    if interrupted(&mut result, stop, start, deadline) {
        return result;
    }
    let _processing = ActiveGuard::new(&counters.process);
    result.status = "Processing".into();
    publish(result.clone());
    if config.mod_router_scan {
        let first = match http_get(
            ip,
            port,
            "/",
            &[],
            &config.user_agent,
            config.connect_timeout_ms,
        ) {
            Ok(response) => response,
            Err(error) => {
                result.status = error.status.into();
                result.info = error.detail;
                return result;
            }
        };
        update_metadata(&mut result, &first);
        result.latency_ms = first.latency_ms;
        publish(result.clone());
        if let Some(error) = &first.body_error {
            result.status = error.status.into();
            result.info = error.detail.clone();
            return result;
        }
        if interrupted(&mut result, stop, start, deadline) {
            return result;
        }
        if !check_filters(filter_rules, &first.body, &first.server, &first.realm) {
            result.status = "Filtered".into();
            return result;
        }
        if first.is_ok() {
            // An unprotected page is already loaded; it must not trigger credential attempts.
            extract_wifi_info(&first.body, &mut result);
            extract_network_info(&first.body, &mut result);
            result.status = "Done".into();
        } else if first.needs_auth() {
            let pairs = build_auth_pairs(config, basic_pairs);
            if first.auth_scheme.eq_ignore_ascii_case("Basic") && !pairs.is_empty() {
                result.status = "Authorizing".into();
                publish(result.clone());
                let cancelled = || stop.load(Ordering::Relaxed) || start.elapsed() >= deadline;
                if let Some((user, pass)) = try_basic_auth(
                    ip,
                    port,
                    "/",
                    &pairs,
                    &config.user_agent,
                    config.connect_timeout_ms,
                    &cancelled,
                ) {
                    result.auth = format!(
                        "{}:{}",
                        if user.is_empty() { "<empty>" } else { &user },
                        if pass.is_empty() { "<empty>" } else { &pass }
                    );
                    let authorization = basic_auth_header(&user, &pass);
                    match http_get(
                        ip,
                        port,
                        "/",
                        &[("Authorization", &authorization)],
                        &config.user_agent,
                        config.connect_timeout_ms,
                    ) {
                        Ok(response) => {
                            update_metadata(&mut result, &response);
                            extract_wifi_info(&response.body, &mut result);
                            extract_network_info(&response.body, &mut result);
                            if let Some(error) = response.body_error {
                                result.status = error.status.into();
                                result.info = error.detail;
                            } else {
                                result.status = if response.is_ok() {
                                    "Done".into()
                                } else {
                                    format!("HTTP {}", response.status)
                                };
                            }
                        }
                        Err(error) => {
                            result.status = error.status.into();
                            result.info = error.detail;
                        }
                    }
                } else {
                    result.status = "Auth failed".into();
                }
                if interrupted(&mut result, stop, start, deadline) {
                    return result;
                }
            } else {
                result.status = "Auth required".into();
                result
                    .info
                    .push_str(if first.auth_scheme.eq_ignore_ascii_case("Digest") {
                        "; Digest authentication is not supported"
                    } else if pairs.is_empty() {
                        "; no credentials configured"
                    } else {
                        "; authentication method is not supported"
                    });
            }
        } else if (300..400).contains(&first.status) {
            result.status = "Redirect".into();
        } else {
            result.status = format!("HTTP {}", first.status);
        }
    } else {
        result.status = "Done".into();
        result.info = "TCP port open; HTTP module disabled".into();
    }
    if config.mod_hnap && result.auth.is_empty() && !interrupted(&mut result, stop, start, deadline)
    {
        let final_status = result.status.clone();
        result.status = "Checking HNAP".into();
        publish(result.clone());
        if let Some(info) = probe_hnap(ip, port, &config.user_agent, config.connect_timeout_ms) {
            result.device_type = info;
        }
        result.status = final_status;
    }
    // pedrib/PoC exploit probes (Pedro Ribeiro, Agile InfoSec — GPLv3)
    if config.mod_pedrib && !interrupted(&mut result, stop, start, deadline) {
        let prev_status = result.status.clone();
        result.status = "Running pedrib probes".into();
        publish(result.clone());
        let hits = run_pedrib_exploits(ip, port, &config.user_agent, config.connect_timeout_ms);
        if let Some(hit) = hits.into_iter().next() {
            merge_exploit_hit(&mut result, hit);
            result.status = "Done".into();
        } else {
            result.status = prev_status;
        }
    }
    // RouterScan-style classic exploit probes (CVE-2013 through CVE-2017)
    if config.mod_rs_exploits && !interrupted(&mut result, stop, start, deadline) {
        let prev_status = result.status.clone();
        result.status = "Running RS exploit probes".into();
        publish(result.clone());
        let hits = crate::rs_exploits::run_rs_exploits(
            ip,
            port,
            &config.user_agent,
            config.connect_timeout_ms,
        );
        if let Some(hit) = hits.into_iter().next() {
            merge_exploit_hit(&mut result, hit);
            result.status = "Done".into();
        } else {
            result.status = prev_status;
        }
    }
    interrupted(&mut result, stop, start, deadline);
    result
}

// ─── Merge exploit hit into scan result ──────────────────────────────────────

fn merge_exploit_hit(result: &mut ScanResult, hit: crate::exploits::ExploitResult) {
    if result.auth.is_empty() && !hit.auth.is_empty() {
        result.auth = hit.auth;
    }
    if result.device_type.is_empty() && !hit.device_type.is_empty() {
        result.device_type = hit.device_type;
    }
    if result.ssid.is_empty() && !hit.ssid.is_empty() {
        result.ssid = hit.ssid;
    }
    if result.wifi_key.is_empty() && !hit.wifi_key.is_empty() {
        result.wifi_key = hit.wifi_key;
    }
    if result.wps_pin.is_empty() && !hit.wps_pin.is_empty() {
        result.wps_pin = hit.wps_pin;
    }
    if result.lan_ip.is_empty() && !hit.lan_ip.is_empty() {
        result.lan_ip = hit.lan_ip;
    }
    if result.wan_ip.is_empty() && !hit.wan_ip.is_empty() {
        result.wan_ip = hit.wan_ip;
    }
    if result.dns.is_empty() && !hit.dns.is_empty() {
        result.dns = hit.dns;
    }
    let tag = format!("[{}|{}] {}", hit.module, hit.cve, hit.comment);
    if result.comment.is_empty() {
        result.comment = tag;
    } else {
        result.comment.push_str("  ");
        result.comment.push_str(&tag);
    }
}

// ─── Build auth pairs ─────────────────────────────────────────────────────────

fn build_auth_pairs(config: &Config, basic_pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    // Custom credentials first
    if config.use_credentials {
        pairs.push((config.cred_user.clone(), config.cred_pass.clone()));
    }
    // Then dictionary
    pairs.extend_from_slice(basic_pairs);
    pairs
}

// ─── Scan mode delays ─────────────────────────────────────────────────────────

fn apply_scan_delay(mode: u8) {
    match mode {
        0 => std::thread::sleep(Duration::from_millis(15)), // Normal
        1 => std::thread::sleep(Duration::from_millis(5)),  // Fast
        2 => {}                                             // Ultra Fast
        _ => {}
    }
}

// ─── Info extraction ─────────────────────────────────────────────────────────

/// Extract Wi-Fi parameters from HTML body using heuristic patterns.
fn extract_wifi_info(body: &str, result: &mut ScanResult) {
    // SSID
    if result.ssid.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["ssid", "wl_ssid", "wifi_ssid", "ap_ssid"]) {
            result.ssid = v;
        }
    }
    // Security type
    if result.security.is_empty() {
        if let Some(v) = extract_value_pattern(
            body,
            &["security_mode", "wl_auth_mode", "wl_akm", "auth_mode"],
        ) {
            result.security = v;
        } else if body.to_ascii_lowercase().contains("wpa2") {
            result.security = "WPA2".into();
        } else if body.to_ascii_lowercase().contains("wpa") {
            result.security = "WPA".into();
        } else if body.to_ascii_lowercase().contains("wep") {
            result.security = "WEP".into();
        }
    }
    // Key / passphrase
    if result.wifi_key.is_empty() {
        if let Some(v) = extract_value_pattern(
            body,
            &["wpa_psk", "wl_wpa_psk", "key", "passphrase", "wl_key"],
        ) {
            result.wifi_key = v;
        }
    }
    // BSSID
    if result.bssid.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["bssid", "wl_hwaddr", "mac_address"]) {
            result.bssid = v;
        }
    }
    // WPS PIN
    if result.wps_pin.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["wps_pin", "wps_device_pin", "pin_code"]) {
            result.wps_pin = v;
        }
    }
}

/// Extract network parameters (LAN/WAN) from HTML body.
fn extract_network_info(body: &str, result: &mut ScanResult) {
    if result.lan_ip.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["lan_ip", "lan_ipaddr", "local_ip"]) {
            result.lan_ip = v;
        }
    }
    if result.lan_mask.is_empty() {
        if let Some(value) =
            extract_value_pattern(body, &["lan_netmask", "lan_mask", "lan_subnet_mask"])
        {
            result.lan_mask = value;
        }
    }
    if result.wan_mask.is_empty() {
        if let Some(value) =
            extract_value_pattern(body, &["wan_netmask", "wan_mask", "wan_subnet_mask"])
        {
            result.wan_mask = value;
        }
    }
    if result.wan_ip.is_empty() {
        if let Some(v) =
            extract_value_pattern(body, &["wan_ip", "wan_ipaddr", "wan_realip", "wanip"])
        {
            result.wan_ip = v;
        }
    }
    if result.dns.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["dns", "wan_dns1", "dns1", "primary_dns"]) {
            result.dns = v;
        }
    }
    if result.wan_gate.is_empty() {
        if let Some(v) = extract_value_pattern(body, &["gateway", "wan_gateway", "default_gw"]) {
            result.wan_gate = v;
        }
    }
}

/// Look for HTML input/select value patterns:
/// `name="KEY" value="VALUE"` or JS variable assignments `KEY = "VALUE"`.
fn extract_value_pattern(body: &str, keys: &[&str]) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    for &key in keys {
        // HTML input: value="..." near name="key"
        if let Some(pos) = lower.find(&format!("name=\"{}\"", key)) {
            if let Some(v) = extract_html_input_value(&body[pos..]) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        // JS: key = "value" or key = 'value'
        if let Some(pos) = lower.find(&format!("{} = \"", key)) {
            let rest = &body[pos + key.len() + 4..];
            if let Some(end) = rest.find('"') {
                let val = &rest[..end];
                if !val.is_empty() && val.len() < 256 {
                    return Some(val.to_string());
                }
            }
        }
        if let Some(pos) = lower.find(&format!("{}=", key)) {
            let rest = &body[pos + key.len() + 1..].trim_start_matches(['"', '\'']);
            // skip if it looks like HTML attribute junk
            if rest.starts_with(|c: char| {
                c.is_ascii_alphanumeric() || c == '-' || c == ':' || c == '.'
            }) {
                let end = rest
                    .find(['"', '\'', ' ', '\n', '<'])
                    .unwrap_or(rest.len().min(64));
                let val = &rest[..end];
                if !val.is_empty() && val.len() < 128 {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn extract_html_input_value(fragment: &str) -> Option<String> {
    let lower = fragment.to_ascii_lowercase();
    // Find "value=" within the next ~300 chars
    let mut boundary = lower.len().min(300);
    while !lower.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let search_area = &lower[..boundary];
    let pos = search_area.find("value=\"")?;
    let rest = &fragment[pos + 7..];
    let end = rest.find('"')?;
    let val = &rest[..end];
    if val.len() < 256 {
        Some(val.to_string())
    } else {
        None
    }
}

// ─── Filter rules loader ─────────────────────────────────────────────────────

fn load_filter_rules() -> Vec<FilterRule> {
    let content = std::fs::read_to_string("filter.txt").unwrap_or_default();
    parse_filter_rules(&content)
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use crate::test_support::{serve, Reply};
    use std::cell::RefCell;

    fn configuration(port: u16) -> Config {
        Config {
            ranges: vec!["127.0.0.1".into()],
            ports: vec![port],
            threads: 1,
            scan_mode: 2,
            connect_timeout_ms: 500,
            mod_hnap: false,
            mod_pedrib: false,
            mod_rs_exploits: false,
            auth_basic_file: "nonexistent-fixture-credentials.txt".into(),
            ..Default::default()
        }
    }

    fn run_reply(reply: Reply) -> (ScanResult, Vec<ScanResult>) {
        let (port, server) = serve(vec![reply]);
        let counters = Counters::default();
        let updates = RefCell::new(Vec::new());
        let result = process_target(
            (Ipv4Addr::LOCALHOST, port),
            &configuration(port),
            &[],
            &[],
            &counters,
            &AtomicBool::new(false),
            &|r| updates.borrow_mut().push(r),
        );
        server.join().unwrap();
        assert_eq!(counters.connect.load(Ordering::Relaxed), 0);
        assert_eq!(counters.process.load(Ordering::Relaxed), 0);
        (result, updates.into_inner())
    }

    #[test]
    fn live_rows_arrive_before_the_http_request_finishes() {
        let (release, gate) = std::sync::mpsc::channel();
        let mut reply = Reply::new(
            "200 OK",
            "Server: FixtureHTTP/1.0\r\n",
            "<title class='device'>Router &amp; Gateway</title>",
        );
        reply.gate = Some(gate);
        let (port, server) = serve(vec![reply]);
        let (tx, rx) = crossbeam_channel::unbounded();
        let worker = std::thread::spawn(move || {
            let mut config = configuration(port);
            config.use_credentials = true;
            config.cred_user = "fixture".into();
            process_target(
                (Ipv4Addr::LOCALHOST, port),
                &config,
                &[],
                &[],
                &Counters::default(),
                &AtomicBool::new(false),
                &|r| {
                    tx.send(r).unwrap();
                },
            )
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap().status,
            "Connecting"
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap().status,
            "Processing"
        );
        assert!(!worker.is_finished());
        release.send(()).unwrap();
        let result = worker.join().unwrap();
        assert_eq!(result.status, "Done");
        assert_eq!(result.server_name, "FixtureHTTP/1.0");
        assert_eq!(result.device_type, "Router & Gateway");
        assert!(
            result.auth.is_empty(),
            "public pages must not be falsely marked authorized"
        );
        assert_eq!(
            server.join().unwrap().len(),
            1,
            "public pages need only one request"
        );
    }

    #[test]
    fn authentication_required_is_terminal_and_preserves_raw_realm() {
        for scheme in ["Basic", "Digest"] {
            let reply = Reply::new("401 Unauthorized",&format!("Server: EmbeddedWeb/2\r\nWWW-Authenticate: {scheme} realm=\"Office Gateway\"\r\n"),"");
            let (result, _) = run_reply(reply);
            assert_eq!(result.status, "Auth required");
            assert!(!result.is_loading());
            assert_eq!(result.server_name, "EmbeddedWeb/2");
            assert_eq!(result.realm, "Office Gateway");
            assert!(result.device_summary().contains("Office Gateway"));
        }
    }

    #[test]
    fn body_timeout_retains_server_and_error_details() {
        let mut reply = Reply::new("200 OK", "Server: SlowDevice\r\n", "<title>Delayed</title>");
        reply.body_delay = Duration::from_millis(800);
        let (result, _) = run_reply(reply);
        assert_eq!(result.status, "Timed out", "{}", result.info);
        assert_eq!(result.server_name, "SlowDevice");
        assert!(!result.info.is_empty());
    }

    #[test]
    fn http_failure_preserves_identification_instead_of_blank_rows() {
        let (result, _) = run_reply(Reply::new(
            "404 Not Found",
            "Server: CustomDevice\r\n",
            "<title>Control Panel</title>",
        ));
        assert_eq!(result.status, "HTTP 404");
        assert_eq!(result.device_type, "Control Panel");
        assert!(result.device_summary().contains("CustomDevice"));
    }

    #[test]
    fn closed_ports_finish_and_never_count_as_found() {
        // Reserve a port without listening, so other parallel fixtures cannot reuse it.
        let reserved = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        reserved
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        let port = reserved.local_addr().unwrap().as_socket().unwrap().port();
        let counters = Counters::default();
        let result = process_target(
            (Ipv4Addr::LOCALHOST, port),
            &configuration(port),
            &[],
            &[],
            &counters,
            &AtomicBool::new(false),
            &|_| {},
        );
        assert!(
            matches!(result.status.as_str(), "Closed" | "Timed out"),
            "{}",
            result.info
        );
        assert!(!result.tcp_open);
        assert!(!result.info.is_empty());
        assert_eq!(counters.connect.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn disabled_http_module_does_not_leave_processing_or_active_counters() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut config = configuration(port);
        config.mod_router_scan = false;
        let counters = Counters::default();
        let result = process_target(
            (Ipv4Addr::LOCALHOST, port),
            &config,
            &[],
            &[],
            &counters,
            &AtomicBool::new(false),
            &|_| {},
        );
        assert_eq!(result.status, "Done");
        assert!(result.tcp_open);
        assert_eq!(counters.connect.load(Ordering::Relaxed), 0);
        assert_eq!(counters.process.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn coordinator_sends_final_statistics_and_stops_the_ticker() {
        let (port, server) = serve(vec![Reply::new(
            "200 OK",
            "Server: Fixture\r\n",
            "<title>Router</title>",
        )]);
        let rx = start_scan(
            Arc::new(configuration(port)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let mut final_stats = ScanStats::default();
        let mut stages = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                ScanMsg::Result(result) => stages.push(result.status),
                ScanMsg::Stats(stats) => final_stats = stats,
                ScanMsg::Done => break,
                ScanMsg::Error(error) => panic!("Unexpected scan startup error: {error}"),
            }
        }
        assert!(
            stages.contains(&"Connecting".into())
                && stages.contains(&"Processing".into())
                && stages.contains(&"Done".into())
        );
        assert_eq!(
            (
                final_stats.total,
                final_stats.completed,
                final_stats.found,
                final_stats.failed
            ),
            (1, 1, 1, 0)
        );
        assert_eq!(
            (
                final_stats.active_connect,
                final_stats.active_process,
                final_stats.queued
            ),
            (0, 0, 0)
        );
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(500)),
                Err(crossbeam_channel::RecvTimeoutError::Disconnected)
            ),
            "ticker must terminate after Done"
        );
        server.join().unwrap();
    }
}

#[cfg(test)]
mod startup_message_tests {
    use super::*;
    #[test]
    fn invalid_range_reports_an_error_instead_of_done_with_zero_targets() {
        let config = Config {
            ranges: vec!["not an IP range".into()],
            ..Default::default()
        };
        let rx = start_scan(
            Arc::new(config),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(1)).unwrap(),ScanMsg::Error(message) if message.contains("line 1"))
        );
    }
}

#[cfg(test)]
mod spaced_cidr_integration_tests {
    use super::*;
    use crate::test_support::{serve, Reply};
    #[test]
    fn spaced_cidr_starts_and_finishes_on_a_loopback_http_service() {
        let (port, server) = serve(vec![Reply::new(
            "200 OK",
            "Server: StartupFixture\r\n",
            "<title>Local test device</title>",
        )]);
        let config = Config {
            ranges: vec!["127.0.0.1 / 32".into()],
            ports: vec![port],
            threads: 1,
            scan_mode: 2,
            connect_timeout_ms: 1000,
            mod_hnap: false,
            mod_pedrib: false,
            mod_rs_exploits: false,
            auth_basic_file: "nonexistent-fixture-credentials.txt".into(),
            ..Default::default()
        };
        let rx = start_scan(
            Arc::new(config),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let mut loaded = false;
        loop {
            match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                ScanMsg::Result(row) => {
                    if row.status == "Done" {
                        assert_eq!(row.server_name, "StartupFixture");
                        assert!(row.is_found());
                        loaded = true;
                    }
                }
                ScanMsg::Stats(_) => {}
                ScanMsg::Done => break,
                ScanMsg::Error(error) => panic!("Valid spaced CIDR failed: {error}"),
            }
        }
        assert!(loaded, "scan must produce a working service result");
        server.join().unwrap();
    }
}

#[cfg(test)]
mod existing_response_metadata_tests {
    use super::*;
    #[test]
    fn subnet_and_dns_metadata_from_an_existing_response_is_preserved() {
        let body = r#"lan_ip = "192.0.2.1"; lan_netmask = "255.255.255.0"; wan_ip = "198.51.100.1"; wan_netmask = "255.255.255.252"; primary_dns = "192.0.2.53";"#;
        let mut row = ScanResult::default();
        extract_network_info(body, &mut row);
        assert_eq!(row.lan_ip, "192.0.2.1");
        assert_eq!(row.lan_mask, "255.255.255.0");
        assert_eq!(row.wan_ip, "198.51.100.1");
        assert_eq!(row.wan_mask, "255.255.255.252");
        assert_eq!(row.dns, "192.0.2.53");
    }
}

#[cfg(test)]
mod non_http_discovery_tests {
    use super::*;
    use crate::test_support::{serve, Reply};
    #[test]
    fn an_open_port_with_no_usable_response_is_excluded_from_visible_results() {
        let mut reply = Reply::new("200 OK", "", "");
        reply.headers = "RTSP/1.0 200 OK\r\nConnection: close\r\n\r\n".into();
        let (port, server) = serve(vec![reply]);
        let config = Config {
            ranges: vec!["127.0.0.1".into()],
            ports: vec![port],
            threads: 1,
            scan_mode: 2,
            connect_timeout_ms: 1000,
            mod_hnap: false,
            mod_pedrib: false,
            mod_rs_exploits: false,
            auth_basic_file: "nonexistent-fixture-credentials.txt".into(),
            ..Default::default()
        };
        let rx = start_scan(
            Arc::new(config),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let mut final_row = None;
        let mut final_stats = ScanStats::default();
        loop {
            match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                ScanMsg::Result(row) => final_row = Some(row),
                ScanMsg::Stats(stats) => final_stats = stats,
                ScanMsg::Done => break,
                ScanMsg::Error(error) => panic!("{error}"),
            }
        }
        let row = final_row.unwrap();
        assert!(row.tcp_open);
        assert_eq!(row.http_status, 0);
        assert!(!row.is_found());
        assert_eq!(row.discovery_status(), "Open");
        assert_eq!(final_stats.found, 1);
        server.join().unwrap();
    }
}
