use crate::models::Config;
use std::collections::HashMap;

const CONFIG_PATH: &str = "config.ini";

/// Establish a writable working directory before creating any UI or worker threads.
/// Existing relative config, credential, filter and export paths share this location.
pub fn init_data_directory() -> std::io::Result<()> {
    let directory = data_directory(
        std::env::var_os("NRM_DATA_DIR"),
        std::env::var_os("LOCALAPPDATA"),
    )?;
    std::fs::create_dir_all(&directory)?;
    std::env::set_current_dir(directory)
}

fn data_directory(
    override_dir: Option<std::ffi::OsString>,
    local_app_data: Option<std::ffi::OsString>,
) -> std::io::Result<std::path::PathBuf> {
    if let Some(path) = override_dir.filter(|p| !p.is_empty()) {
        return Ok(path.into());
    }
    if let Some(path) = local_app_data.filter(|p| !p.is_empty()) {
        return Ok(std::path::PathBuf::from(path).join("No-Router-Mercy"));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "LOCALAPPDATA is unavailable; set NRM_DATA_DIR to a writable folder",
    ))
}

// ─── INI helpers ─────────────────────────────────────────────────────────────

pub fn load_ini(path: &str) -> HashMap<String, HashMap<String, String>> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    parse_ini(&content)
}

fn parse_ini(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut section = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
            result.entry(section.clone()).or_default();
        } else if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let val = line[eq + 1..].to_string(); // keep trailing spaces intentionally
            result.entry(section.clone()).or_default().insert(key, val);
        }
    }
    result
}

fn get(ini: &HashMap<String, HashMap<String, String>>, sec: &str, key: &str, def: &str) -> String {
    ini.get(sec)
        .and_then(|s| s.get(key))
        .cloned()
        .unwrap_or_else(|| def.to_string())
}

fn get_bool(
    ini: &HashMap<String, HashMap<String, String>>,
    sec: &str,
    key: &str,
    def: bool,
) -> bool {
    let v = get(ini, sec, key, if def { "1" } else { "0" });
    v.trim() != "0" && v.trim() != "false" && !v.trim().is_empty()
}

fn get_u32(ini: &HashMap<String, HashMap<String, String>>, sec: &str, key: &str, def: u32) -> u32 {
    get(ini, sec, key, "").trim().parse().unwrap_or(def)
}

fn get_u16(ini: &HashMap<String, HashMap<String, String>>, sec: &str, key: &str, def: u16) -> u16 {
    get(ini, sec, key, "").trim().parse().unwrap_or(def)
}

fn get_u64(ini: &HashMap<String, HashMap<String, String>>, sec: &str, key: &str, def: u64) -> u64 {
    get(ini, sec, key, "").trim().parse().unwrap_or(def)
}

fn get_u8(ini: &HashMap<String, HashMap<String, String>>, sec: &str, key: &str, def: u8) -> u8 {
    get(ini, sec, key, "").trim().parse().unwrap_or(def)
}

// ─── Load config ─────────────────────────────────────────────────────────────

pub fn load_config() -> Config {
    let ini = load_ini(CONFIG_PATH);

    // Parse port list from PortScan.Ports file
    let ports_file = get(&ini, "PortScan", "Ports", "ports.txt");
    let ports = load_ports_file(&ports_file);

    // Parse ranges from PortScan.Ranges file
    let ranges_file = get(&ini, "PortScan", "Ranges", "ranges.txt");
    let ranges = load_ranges_file(&ranges_file);

    Config {
        threads: get_u32(&ini, "PortScan", "Threads", 300),
        connect_timeout_ms: get_u64(&ini, "PortScan", "Timeout.Connect.Value", 2000),
        thread_timeout_min: get_u32(&ini, "PortScan", "Timeout.Thread.Minutes", 5),
        scan_mode: get_u8(&ini, "PortScan", "ScanMode", 0),

        ports,
        ranges,

        user_agent: get(
            &ini,
            "HTTP",
            "UserAgent",
            "Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
        ),
        proxy_type: get_u8(&ini, "HTTP", "Proxy.Type", 0),
        proxy_ip: get(&ini, "HTTP", "Proxy.IP", "127.0.0.1"),
        proxy_port: get_u16(&ini, "HTTP", "Proxy.Port", 8888),
        proxy_use_auth: get_bool(&ini, "HTTP", "Proxy.UseAuth", false),
        proxy_user: get(&ini, "HTTP", "Proxy.User", ""),
        proxy_pass: get(&ini, "HTTP", "Proxy.Pass", ""),

        auth_basic_file: get(&ini, "RouterScan", "Auth.Basic.PairFile", "auth_basic.txt"),
        auth_digest_file: get(
            &ini,
            "RouterScan",
            "Auth.Digest.PairFile",
            "auth_digest.txt",
        ),
        auth_form_file: get(&ini, "RouterScan", "Auth.Form.PairFile", "auth_form.txt"),
        use_credentials: get_bool(&ini, "RouterScan", "Auth.Custom.Enable", false),
        cred_user: get(&ini, "RouterScan", "Auth.Custom.Username", "admin"),
        cred_pass: get(&ini, "RouterScan", "Auth.Custom.Password", ""),

        mod_router_scan: get_bool(&ini, "Modules", "RouterScan", true),
        mod_proxy_check: get_bool(&ini, "Modules", "ProxyCheck", false),
        mod_hnap: get_bool(&ini, "Modules", "HNAP", true),
        mod_sqlite: get_bool(&ini, "Modules", "SQLite", false),
        mod_hudson: get_bool(&ini, "Modules", "Hudson", false),
        mod_pma: get_bool(&ini, "Modules", "PMA", false),
        mod_pedrib: get_bool(&ini, "Modules", "PedribExploits", true),
        mod_rs_exploits: get_bool(&ini, "Modules", "RSExploits", true),

        autosave_enabled: get_bool(&ini, "Output", "AutoSave", false),
        autosave_interval: get_u32(&ini, "Output", "Interval", 300),
        autosave_format: get(&ini, "Output", "Format", "txt"),
        upload_server: get(
            &ini,
            "Output",
            "Upload.Server",
            "https://3wifi.dev/upload", // p3wifi.ru successor; stascorp.com is defunct
        ),
        upload_username: get(&ini, "Output", "Upload.Username", ""),
        upload_password: get(&ini, "Output", "Upload.Password", ""),

        good_filter_flags: get_u8(&ini, "GUI", "Tab.Good.Flags", 0x0F),
        geolocation_provider: get_u8(&ini, "GUI", "Geolocation.Provider", 2),
        follow_realtime: get_bool(&ini, "GUI", "Tab.Realtime.Follow", true),
        follow_good: get_bool(&ini, "GUI", "Tab.Good.Follow", true),
    }
}

fn load_ports_file(path: &str) -> Vec<u16> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut ports: Vec<u16> = content
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    if ports.is_empty() {
        ports = vec![80, 8080, 443, 8443, 8008, 81, 8081, 8888, 10000];
    }
    ports
}

fn load_ranges_file(path: &str) -> Vec<String> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let ranges: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if ranges.is_empty() {
        vec!["192.168.1.0/24".into()]
    } else {
        ranges
    }
}

// ─── Save config ─────────────────────────────────────────────────────────────

pub fn save_config(cfg: &Config) {
    // Save ports.txt and ranges.txt
    let ports_content = cfg
        .ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write("ports.txt", ports_content);

    let ranges_content = cfg.ranges.join("\n");
    let _ = std::fs::write("ranges.txt", ranges_content);

    let ini = build_ini(cfg);
    let _ = std::fs::write(CONFIG_PATH, ini);
}

fn build_ini(c: &Config) -> String {
    let mut s = String::new();

    s.push_str("[PortScan]\n");
    s.push_str(&format!("ScanMode={}\n", c.scan_mode));
    s.push_str(&format!("Threads={}\n", c.threads));
    s.push_str(&format!("Timeout.Connect.Value={}\n", c.connect_timeout_ms));
    s.push_str(&format!(
        "Timeout.Thread.Minutes={}\n",
        c.thread_timeout_min
    ));
    s.push_str("Ranges=ranges.txt\n");
    s.push_str("Ports=ports.txt\n\n");

    s.push_str("[Output]\n");
    s.push_str(&format!("AutoSave={}\n", c.autosave_enabled as u8));
    s.push_str(&format!("Interval={}\n", c.autosave_interval));
    s.push_str(&format!("Format={}\n", c.autosave_format));
    s.push_str(&format!("Upload.Server={}\n", c.upload_server));
    s.push_str(&format!("Upload.Username={}\n", c.upload_username));
    s.push_str(&format!("Upload.Password={}\n\n", c.upload_password));

    s.push_str("[HTTP]\n");
    s.push_str(&format!("Proxy.Type={}\n", c.proxy_type));
    s.push_str(&format!("Proxy.IP={}\n", c.proxy_ip));
    s.push_str(&format!("Proxy.Port={}\n", c.proxy_port));
    s.push_str(&format!("Proxy.UseAuth={}\n", c.proxy_use_auth as u8));
    s.push_str(&format!("Proxy.User={}\n", c.proxy_user));
    s.push_str(&format!("Proxy.Pass={}\n", c.proxy_pass));
    s.push_str(&format!("UserAgent={}\n\n", c.user_agent));

    s.push_str("[Modules]\n");
    s.push_str(&format!("RouterScan={}\n", c.mod_router_scan as u8));
    s.push_str(&format!("ProxyCheck={}\n", c.mod_proxy_check as u8));
    s.push_str(&format!("HNAP={}\n", c.mod_hnap as u8));
    s.push_str(&format!("SQLite={}\n", c.mod_sqlite as u8));
    s.push_str(&format!("Hudson={}\n", c.mod_hudson as u8));
    s.push_str(&format!("PMA={}\n", c.mod_pma as u8));
    s.push_str(&format!("PedribExploits={}\n", c.mod_pedrib as u8));
    s.push_str(&format!("RSExploits={}\n\n", c.mod_rs_exploits as u8));

    s.push_str("[RouterScan]\n");
    s.push_str(&format!("Auth.Basic.PairFile={}\n", c.auth_basic_file));
    s.push_str(&format!("Auth.Digest.PairFile={}\n", c.auth_digest_file));
    s.push_str(&format!("Auth.Form.PairFile={}\n", c.auth_form_file));
    s.push_str(&format!("Auth.Custom.Enable={}\n", c.use_credentials as u8));
    s.push_str(&format!("Auth.Custom.Username={}\n", c.cred_user));
    s.push_str(&format!("Auth.Custom.Password={}\n\n", c.cred_pass));

    s.push_str("[GUI]\n");
    s.push_str(&format!("Tab.Good.Flags={}\n", c.good_filter_flags));
    s.push_str(&format!(
        "Geolocation.Provider={}\n",
        c.geolocation_provider
    ));
    s.push_str(&format!(
        "Tab.Realtime.Follow={}\n",
        c.follow_realtime as u8
    ));
    s.push_str(&format!("Tab.Good.Follow={}\n", c.follow_good as u8));

    s
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn explicit_directory_takes_priority_over_user_profile() {
        assert_eq!(
            data_directory(Some("custom-data".into()), Some("profile".into())).unwrap(),
            std::path::PathBuf::from("custom-data")
        );
    }

    #[test]
    fn user_profile_is_used_without_an_override() {
        assert_eq!(
            data_directory(Some("".into()), Some("profile".into())).unwrap(),
            std::path::PathBuf::from("profile").join("No-Router-Mercy")
        );
        assert!(data_directory(None, None).is_err());
    }

    #[test]
    fn saved_config_roundtrips_through_the_ini_parser() {
        let config = Config::default();
        let ini = parse_ini(&build_ini(&config));
        assert_eq!(
            get(&ini, "RouterScan", "Auth.Custom.Password", "missing"),
            ""
        );
        assert_eq!(get_u32(&ini, "PortScan", "Threads", 0), config.threads);
        assert_eq!(
            get_bool(&ini, "Modules", "RSExploits", false),
            config.mod_rs_exploits
        );
    }
}
