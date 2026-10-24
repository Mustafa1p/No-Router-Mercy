use crate::models::ScanResult;

// Widths are relative weights; every column shares the available window width.
pub const COLUMNS: [(&str, f32); 20] = [
    ("IP Address", 110.0),
    ("Port", 42.0),
    ("Time (ms)", 54.0),
    ("Status", 78.0),
    ("Authorization", 94.0),
    ("Device type", 110.0),
    ("Server name", 105.0),
    ("Realm", 90.0),
    ("BSSID", 100.0),
    ("ESSID", 90.0),
    ("Security", 68.0),
    ("Key", 92.0),
    ("WPS PIN", 65.0),
    ("LAN IP", 95.0),
    ("LAN subnet", 95.0),
    ("WAN IP", 95.0),
    ("WAN subnet", 95.0),
    ("Domain name server", 115.0),
    ("Info", 110.0),
    ("Comment", 100.0),
];

pub fn widths(available: f32) -> Vec<f32> {
    let total: f32 = COLUMNS.iter().map(|(_, weight)| *weight).sum();
    let mut values: Vec<f32> = COLUMNS
        .iter()
        .map(|(_, weight)| available * weight / total)
        .collect();
    let used: f32 = values.iter().take(values.len() - 1).sum();
    *values.last_mut().unwrap() = available - used;
    values
}

pub fn values(r: &ScanResult) -> [String; 20] {
    [
        r.ip.clone(),
        r.port.to_string(),
        r.latency_ms.to_string(),
        r.discovery_status().to_owned(),
        r.auth.clone(),
        r.device_type.clone(),
        r.server_name.clone(),
        r.realm.clone(),
        r.bssid.clone(),
        r.ssid.clone(),
        r.security.clone(),
        r.wifi_key.clone(),
        r.wps_pin.clone(),
        r.lan_ip.clone(),
        r.lan_mask.clone(),
        r.wan_ip.clone(),
        r.wan_mask.clone(),
        r.dns.clone(),
        r.info.clone(),
        r.comment.clone(),
    ]
}

pub fn clipboard(rows: &[&ScanResult], include_header: bool) -> String {
    let mut lines = Vec::new();
    if include_header {
        lines.push(
            COLUMNS
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join("\t"),
        );
    }
    for row in rows {
        lines.push(
            values(row)
                .iter()
                .map(|v| v.replace(['\t', '\r', '\n'], " "))
                .collect::<Vec<_>>()
                .join("\t"),
        );
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_columns_fit_the_window_without_horizontal_overflow() {
        for available in [1140.0, 1490.0, 1860.0] {
            let widths = widths(available);
            assert_eq!(widths.len(), 20);
            assert!((widths.iter().sum::<f32>() - available).abs() < 0.02);
            assert!(widths.iter().all(|w| *w > 20.0));
        }
    }
    #[test]
    fn requested_columns_copy_the_exact_corresponding_values() {
        let row = ScanResult {
            ssid: "Office Wi-Fi".into(),
            bssid: "02:00:00:00:00:01".into(),
            security: "WPA2".into(),
            wifi_key: "provided-example-key".into(),
            wps_pin: "12345670".into(),
            lan_ip: "192.0.2.1".into(),
            lan_mask: "255.255.255.0".into(),
            wan_ip: "198.51.100.1".into(),
            wan_mask: "255.255.255.252".into(),
            dns: "192.0.2.53, 192.0.2.54".into(),
            ..Default::default()
        };
        let result = clipboard(&[&row], true);
        let lines: Vec<_> = result.lines().collect();
        let headers: Vec<_> = lines[0].split('\t').collect();
        let cells: Vec<_> = lines[1].split('\t').collect();
        assert_eq!(headers.len(), 20);
        assert_eq!(cells.len(), 20);
        for (name, expected) in [
            ("ESSID", "Office Wi-Fi"),
            ("LAN subnet", "255.255.255.0"),
            ("WAN subnet", "255.255.255.252"),
            ("Domain name server", "192.0.2.53, 192.0.2.54"),
            ("Key", "provided-example-key"),
            ("WPS PIN", "12345670"),
        ] {
            assert_eq!(
                cells[headers.iter().position(|h| *h == name).unwrap()],
                expected
            );
        }
    }
}
