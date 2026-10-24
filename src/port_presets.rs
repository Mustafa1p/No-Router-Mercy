//! TCP inventory profiles. Numeric Top-N ordering from Nmap nmap-services,
//! retrieved 2026-10-23; only numeric ranking facts are retained.
//! https://nmap.org/book/port-scanning-options.html
//! https://raw.githubusercontent.com/nmap/nmap/master/nmap-services
//! Category lists are curated starting points, not frequency rankings.

pub const TOP_TCP: [u16; 100] = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];
pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub ports: &'static [u16],
}
pub fn presets() -> Vec<Preset> {
    vec![
        Preset { name: "Top 10 TCP", description: "10 most frequent open TCP ports in Nmap frequency data.", ports: &TOP_TCP[..10] },
        Preset { name: "Top 50 TCP", description: "50 most frequent open TCP ports in Nmap frequency data.", ports: &TOP_TCP[..50] },
        Preset { name: "Top 100 TCP", description: "100 most frequent open TCP ports in Nmap frequency data.", ports: &TOP_TCP },
        Preset { name: "Web / Servers", description: "Common web, file, mail, directory and remote administration services (TCP).", ports: &[21,22,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,2049,3000,3389,5900,8000,8008,8080,8081,8443,8888,9000,9090,9443] },
        Preset { name: "Databases / SQL", description: "Common SQL engines plus Redis, MongoDB, search and cache services (TCP).", ports: &[1433,1521,1526,2483,2484,3050,3306,33060,5000,5432,6379,7474,7687,9042,9160,9200,9300,11211,27017,27018,27019,50000] },
        Preset { name: "SQL Databases", description: "Common SQL Server, Oracle, MySQL, PostgreSQL, Firebird and DB2 listener ports (TCP).", ports: &[1433,1521,1526,2483,2484,3050,3306,33060,5432,50000] },
        Preset { name: "Routers / Network", description: "Common TCP management and web interfaces. Does not include UDP SNMP or discovery.", ports: &[22,23,53,80,81,443,8291,8728,8729,8000,8001,8008,8080,8081,8443,8888,9000,9443,10000] },
        Preset { name: "IP Cameras / Video", description: "Common web, RTSP and vendor-configurable video service ports (TCP). UDP discovery is not scanned.", ports: &[80,81,443,554,1935,5000,7001,8000,8001,8080,8081,8443,8554,8899,9000,10554,34567,37777] },
    ]
}
pub fn summary(ports: &[u16]) -> String {
    let mut unique = ports.to_vec();
    unique.sort_unstable();
    unique.dedup();
    for preset in presets() {
        let mut candidate = preset.ports.to_vec();
        candidate.sort_unstable();
        if candidate == unique {
            return format!("{} ({})", preset.name, unique.len());
        }
    }
    format!("Custom ({} TCP)", unique.len())
}
/// A port number is a service hint, never a detected identity.
pub fn service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        81 | 8000 | 8001 | 8008 | 8080 | 8081 | 8888 => "Web alt.",
        110 | 995 => "POP3",
        135 => "MS RPC",
        139 => "NetBIOS",
        143 | 993 => "IMAP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        554 | 8554 | 10554 => "RTSP",
        636 => "LDAPS",
        1433 => "SQL Server",
        1521 | 1526 | 2483 | 2484 => "Oracle",
        1935 => "RTMP",
        2049 => "NFS",
        3050 => "Firebird",
        3306 | 33060 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        7474 | 7687 => "Neo4j",
        8291 => "Winbox",
        8443 | 9443 => "HTTPS alt.",
        8728 | 8729 => "Router API",
        9042 | 9160 => "Cassandra",
        9100 => "Printing",
        9200 | 9300 => "Elasticsearch",
        11211 => "Memcached",
        27017..=27019 => "MongoDB",
        50000 => "DB2",
        _ => "TCP",
    }
}
pub fn port_label(port: u16) -> String {
    format!("{port}  {}", service(port))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn top_lists_are_nested_unique_and_have_exact_counts() {
        let all = presets();
        for (p, n) in all.iter().take(3).zip([10, 50, 100]) {
            assert_eq!(p.ports.len(), n);
            let mut v = p.ports.to_vec();
            v.sort_unstable();
            v.dedup();
            assert_eq!(v.len(), n);
            assert!(!v.contains(&0));
            assert_eq!(p.ports, &TOP_TCP[..n]);
        }
        assert_eq!(
            &TOP_TCP[..10],
            &[80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]
        );
    }
    #[test]
    fn summaries_are_compact_and_survive_persisted_reordering() {
        let mut p = TOP_TCP.to_vec();
        p.reverse();
        p.push(80);
        assert_eq!(summary(&p), "Top 100 TCP (100)");
        assert_eq!(summary(&[12345]), "Custom (1 TCP)");
        assert!(summary(&(1..=65535).collect::<Vec<_>>()).len() < 30);
    }
    #[test]
    fn categories_have_distinct_valid_tcp_ports() {
        for p in presets() {
            let mut v = p.ports.to_vec();
            v.sort_unstable();
            v.dedup();
            assert_eq!(v.len(), p.ports.len());
            assert!(!v.contains(&0));
        }
        assert_eq!(service(5432), "PostgreSQL");
        assert!(presets()
            .iter()
            .find(|p| p.name == "SQL Databases")
            .unwrap()
            .ports
            .contains(&3306));
    }
}
