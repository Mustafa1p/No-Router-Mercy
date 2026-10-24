use crate::models::ScanResult;
use std::fmt::Write;

const HEADERS: [&str; 23] = [
    "IP", "Port", "Time", "Status", "Auth", "Type", "BSSID", "SSID", "Security", "Key", "WPS",
    "LAN_IP", "LAN_Mask", "WAN_IP", "WAN_Mask", "WAN_Gate", "DNS", "Lat", "Lon", "Comment",
    "Server", "Realm", "Info",
];

fn result_values(r: &ScanResult) -> [String; 23] {
    [
        r.ip.clone(),
        r.port.to_string(),
        r.latency_ms.to_string(),
        r.status.clone(),
        r.auth.clone(),
        r.device_type.clone(),
        r.bssid.clone(),
        r.ssid.clone(),
        r.security.clone(),
        r.wifi_key.clone(),
        r.wps_pin.clone(),
        r.lan_ip.clone(),
        r.lan_mask.clone(),
        r.wan_ip.clone(),
        r.wan_mask.clone(),
        r.wan_gate.clone(),
        r.dns.clone(),
        r.latitude.to_string(),
        r.longitude.to_string(),
        r.comment.clone(),
        r.server_name.clone(),
        r.realm.clone(),
        r.info.clone(),
    ]
}

/// Original columns retain their order; raw metadata and errors are appended.
pub fn export_txt(results: &[ScanResult]) -> String {
    let mut out = HEADERS.join("\t");
    out.push('\n');
    for r in results {
        let _ = writeln!(
            out,
            "{}",
            result_values(r)
                .iter()
                .map(|v| v.replace(['\t', '\r', '\n'], " "))
                .collect::<Vec<_>>()
                .join("\t")
        );
    }
    out
}

pub fn export_csv(results: &[ScanResult]) -> String {
    let mut out = HEADERS
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    for r in results {
        let _ = writeln!(
            out,
            "{}",
            result_values(r)
                .iter()
                .map(|v| csv_field(v))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Export results to JSON.
pub fn export_json(results: &[ScanResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|_| "[]".into())
}

/// Export results as IP:Port list.
pub fn export_ipport(results: &[ScanResult]) -> String {
    results
        .iter()
        .map(|r| format!("{}:{}", r.ip, r.port))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Save to file with the given format string.
pub fn save_to_file(results: &[ScanResult], path: &str, format: &str) -> Result<(), String> {
    let content = match format {
        "csv" => export_csv(results),
        "json" => export_json(results),
        "ipport" => export_ipport(results),
        _ => export_txt(results),
    };
    std::fs::write(path, content).map_err(|e| e.to_string())
}

/// Return a timestamped filename: `YYYYMMDD_HHMMSS.ext`
/// Uses SYSTEMTIME on Windows via a simple approach.
pub fn timestamped_filename(format: &str) -> String {
    let ext = match format {
        "csv" => "csv",
        "json" => "json",
        "xml" => "xml",
        "ipport" => "txt",
        _ => "txt",
    };
    // Build timestamp from std::time (seconds since epoch, approximate)
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert epoch seconds to Y-M-D H:M:S (UTC, approximate)
    let s = epoch_to_datetime_str(secs);
    format!("{}_{}.{}", &s[..8], &s[8..], ext)
}

fn epoch_to_datetime_str(secs: u64) -> String {
    // Simple UTC date calculation
    let mut s = secs;
    let sec = s % 60;
    s /= 60;
    let min = s % 60;
    s /= 60;
    let hour = s % 24;
    s /= 24;
    // Days since 1970-01-01
    let mut days = s as u32;
    let mut year = 1970u32;
    loop {
        let dy =
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                366
            } else {
                365
            };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let mdays = [
        31u32,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &mdays {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        year, month, day, hour, min, sec
    )
}
