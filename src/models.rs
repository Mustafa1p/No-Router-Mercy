use serde::{Deserialize, Serialize};

// ─── Scan result (one row in the table) ─────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub latency_ms: u64,
    pub status: String,
    pub auth: String,        // "user:pass", exploit name, or ""
    pub device_type: String, // detected server / model
    pub server_name: String,
    pub realm: String,
    pub info: String,
    pub tcp_open: bool,
    pub http_status: u16,
    pub radio_off: bool,
    pub hidden: bool,
    pub bssid: String,
    pub ssid: String,
    pub security: String,
    pub wifi_key: String,
    pub wps_pin: String,
    pub lan_ip: String,
    pub lan_mask: String,
    pub wan_ip: String,
    pub wan_mask: String,
    pub wan_gate: String,
    pub dns: String,
    pub latitude: f64,
    pub longitude: f64,
    pub comment: String,
}

impl ScanResult {
    pub fn is_loading(&self) -> bool {
        matches!(
            self.status.as_str(),
            "Connecting"
                | "Processing"
                | "Authorizing"
                | "Checking HNAP"
                | "Running pedrib probes"
                | "Running RS exploit probes"
        )
    }

    #[cfg(test)]
    pub fn device_summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for value in [&self.device_type, &self.server_name, &self.realm] {
            let value = value.trim();
            if !value.is_empty() && !parts.iter().any(|p| p.eq_ignore_ascii_case(value)) {
                parts.push(value.to_owned());
            }
        }
        if !parts.is_empty() {
            parts.join(" | ")
        } else if self.is_loading() {
            "Loading…".into()
        } else if self.tcp_open {
            "Not identified".into()
        } else {
            "Unavailable".into()
        }
    }

    /// Visible discoveries require a usable HTTP response, not just an open socket.
    pub fn is_found(&self) -> bool {
        self.tcp_open && (100..600).contains(&self.http_status) && !self.inspection_failed()
    }

    pub fn inspection_failed(&self) -> bool {
        matches!(
            self.status.as_str(),
            "Timed out"
                | "Can't connect"
                | "Can't load"
                | "TLS error"
                | "No response"
                | "Interrupted"
                | "Stopped"
        )
    }

    pub fn discovery_status(&self) -> &str {
        if self.tcp_open && self.inspection_failed() {
            "Open"
        } else if self.tcp_open && self.status == "Processing" {
            "Inspecting"
        } else {
            &self.status
        }
    }

    pub fn is_good(&self) -> bool {
        !self.auth.is_empty()
            || !self.ssid.is_empty()
            || !self.wan_ip.is_empty()
            || !self.dns.is_empty()
    }
}

// ─── Application scan state ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AppState {
    #[default]
    Idle,
    Scanning,
    Paused,
    Stopping,
}

// ─── Scan configuration ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Port scanner
    pub threads: u32,
    pub connect_timeout_ms: u64,
    pub thread_timeout_min: u32,
    pub scan_mode: u8, // 0=Normal, 1=Fast, 2=UltraFast

    // Lists
    pub ports: Vec<u16>,
    pub ranges: Vec<String>,

    // HTTP
    pub user_agent: String,
    pub proxy_type: u8, // 0=None, 1=HTTP, 2=HTTPS, 3=CONNECT, 4=SOCKS4, 5=SOCKS4a, 6=SOCKS5
    pub proxy_ip: String,
    pub proxy_port: u16,
    pub proxy_user: String, // Proxy.User — proxy auth username (stParam index 19)
    pub proxy_pass: String, // Proxy.Pass — proxy auth password (stParam index 20)
    pub proxy_use_auth: bool, // Proxy.UseAuth (stParam index 18)

    // Authentication
    pub auth_basic_file: String,
    pub auth_digest_file: String,
    pub auth_form_file: String,
    pub use_credentials: bool,
    pub cred_user: String,
    pub cred_pass: String,

    // Modules
    pub mod_router_scan: bool,
    pub mod_proxy_check: bool,
    pub mod_hnap: bool,
    pub mod_sqlite: bool,
    pub mod_hudson: bool,
    pub mod_pma: bool,
    // pedrib/PoC exploit probes (Pedro Ribeiro, Agile InfoSec — GPLv3)
    pub mod_pedrib: bool,
    // RouterScan-style classic exploit probes (CVE-2013 through CVE-2017)
    pub mod_rs_exploits: bool,

    // Output
    pub autosave_enabled: bool,
    pub autosave_interval: u32,
    pub autosave_format: String,
    pub upload_server: String,
    pub upload_username: String,
    pub upload_password: String,

    // GUI
    pub good_filter_flags: u8,
    pub geolocation_provider: u8,
    pub follow_realtime: bool,
    pub follow_good: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 300,
            connect_timeout_ms: 2000,
            thread_timeout_min: 5,
            scan_mode: 0,
            ports: vec![80, 8080, 443, 8443, 8008, 81, 8081, 8888, 10000],
            ranges: vec!["192.168.1.0/24".into()],
            user_agent: "Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1"
                .into(),
            proxy_type: 0,
            proxy_ip: "127.0.0.1".into(),
            proxy_port: 8888,
            proxy_user: String::new(),
            proxy_pass: String::new(),
            proxy_use_auth: false,
            auth_basic_file: "auth_basic.txt".into(),
            auth_digest_file: "auth_digest.txt".into(),
            auth_form_file: "auth_form.txt".into(),
            use_credentials: false,
            cred_user: "admin".into(),
            cred_pass: String::new(),
            mod_router_scan: true,
            mod_proxy_check: false,
            mod_hnap: true,
            mod_sqlite: false,
            mod_hudson: false,
            mod_pma: false,
            mod_pedrib: true,
            mod_rs_exploits: true, // Classic RouterScan exploit probes — enabled by default
            autosave_enabled: false,
            autosave_interval: 300,
            autosave_format: "txt".into(),
            upload_server: "https://3wifi.dev/upload".into(), // p3wifi successor (3wifi.stascorp.com is down)
            upload_username: String::new(),
            upload_password: String::new(),
            good_filter_flags: 0x0F,
            geolocation_provider: 2,
            follow_realtime: true,
            follow_good: true,
        }
    }
}

// ─── Filter rule ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterRule {
    pub place: String, // "body" | "serv" | "relm"
    pub mode: String,  // "eq" | "neq" | "cnt" | "ncnt"
    pub pattern: String,
}

#[cfg(test)]
mod found_result_tests {
    use super::*;

    #[test]
    fn attempts_and_transport_failures_are_not_found_results() {
        for status in [
            "Connecting",
            "Processing",
            "Closed",
            "Timed out",
            "Can't connect",
            "Can't load",
            "TLS error",
            "No response",
            "Stopped",
            "Interrupted",
            "Filtered",
        ] {
            let row = ScanResult {
                status: status.into(),
                ..Default::default()
            };
            assert!(!row.is_found(), "{status} must be hidden");
        }
        for status in ["Timed out", "Can't load", "TLS error", "Stopped"] {
            let row = ScanResult {
                status: status.into(),
                tcp_open: true,
                http_status: 200,
                ..Default::default()
            };
            assert!(
                !row.is_found(),
                "{status} must remain hidden even with response headers"
            );
        }
    }

    #[test]
    fn open_socket_without_a_response_is_not_a_visible_discovery() {
        let row = ScanResult {
            status: "Processing".into(),
            tcp_open: true,
            ..Default::default()
        };
        assert!(!row.is_found());
    }

    #[test]
    fn responsive_services_do_not_require_successful_authentication() {
        for (status, http_status) in [
            ("Done", 200),
            ("Auth required", 401),
            ("Auth failed", 401),
            ("Redirect", 302),
            ("HTTP 404", 404),
            ("Processing", 200),
        ] {
            let row = ScanResult {
                status: status.into(),
                tcp_open: true,
                http_status,
                ..Default::default()
            };
            assert!(row.is_found(), "responsive {status} must count");
        }
    }
}
