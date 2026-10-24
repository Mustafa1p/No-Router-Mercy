use std::net::Ipv4Addr;

/// Parse a single IP range line into a list of IPv4 addresses.
/// Supported syntaxes:
///   1. Single:      `192.168.1.1`
///   2. Dash range:  `192.168.1.1-192.168.1.254`
///   3. CIDR:        `192.168.1.0/24`
///   4. Nmap-octet:  `10.0.0.1-254`, `10.0.2,4.1`, `192.168.0-10,100.1,254`
///   5. Comments:    `# ...` lines ignored
pub fn parse_range(line: &str) -> Result<Vec<Ipv4Addr>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return Ok(vec![]);
    }

    // CIDR notation: contains '/' and no '-' outside of the octets
    if let Some(slash) = line.find('/') {
        let ip_part = line[..slash].trim();
        let mask_part = line[slash + 1..].trim();
        let base: Ipv4Addr = ip_part
            .parse()
            .map_err(|_| format!("Invalid CIDR base: {}", ip_part))?;
        let bits: u32 = mask_part
            .parse()
            .map_err(|_| format!("Invalid mask: {}", mask_part))?;
        if bits > 32 {
            return Err(format!("Mask out of range: {}", bits));
        }
        return Ok(cidr_expand(base, bits));
    }

    // Full dash range: contains exactly one '-' and both sides are full IPs
    // e.g. 192.168.1.1-192.168.1.254
    if line.contains('-') {
        let parts: Vec<&str> = line.splitn(2, '-').collect();
        if parts.len() == 2 && parts[0].contains('.') && parts[1].contains('.') {
            if let (Ok(start), Ok(end)) = (
                parts[0].trim().parse::<Ipv4Addr>(),
                parts[1].trim().parse::<Ipv4Addr>(),
            ) {
                let s = u32::from(start);
                let e = u32::from(end);
                if e < s {
                    return Err(format!("Range end < start: {}", line));
                }
                return Ok((s..=e).map(Ipv4Addr::from).collect());
            }
        }
    }

    // Nmap-octet syntax (contains ',' or single-octet '-')
    // Every case that doesn't parse as a plain IP goes here
    if is_nmap_octet_syntax(line) {
        return parse_nmap(line);
    }

    // Single IP
    let addr: Ipv4Addr = line
        .parse()
        .map_err(|_| format!("Cannot parse IP range: {}", line))?;
    Ok(vec![addr])
}

fn is_nmap_octet_syntax(s: &str) -> bool {
    // Contains comma, or a '-' that doesn't separate two full IPs
    s.contains(',') || s.contains('-')
}

/// Parse the entire ranges block (multi-line text) into IPs.
#[cfg(test)]
fn parse_all_ranges(text: &str) -> Vec<Ipv4Addr> {
    let mut result = Vec::new();
    for line in text.lines() {
        // Legacy permissive parser is retained only for its historical test cases.
        if let Ok(ips) = parse_range(line) {
            result.extend(ips);
        }
    }
    result
}

/// Strict startup parser: a bad line must not silently become an empty scan.
pub fn parse_all_ranges_checked(text: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut result = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let ips =
            parse_range(line).map_err(|error| format!("IP range line {}: {}", index + 1, error))?;
        result.extend(ips);
    }
    if result.is_empty() {
        return Err("Add at least one IP address or range.".into());
    }
    Ok(result)
}

// ─── CIDR expansion ──────────────────────────────────────────────────────────

fn cidr_expand(base: Ipv4Addr, prefix: u32) -> Vec<Ipv4Addr> {
    if prefix == 32 {
        return vec![base];
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = u32::from(base) & mask;
    let count = 1u64 << (32 - prefix);
    // Cap at 16M to avoid OOM
    let count = count.min(16_777_216) as u32;
    (0..count).map(|i| Ipv4Addr::from(network + i)).collect()
}

// ─── Nmap octet-range parser ─────────────────────────────────────────────────

fn parse_octet_part(s: &str) -> Result<Vec<u8>, String> {
    let mut values = Vec::new();
    for segment in s.split(',') {
        let segment = segment.trim();
        if let Some(dash) = segment.find('-') {
            let lo: u16 = segment[..dash]
                .trim()
                .parse()
                .map_err(|_| format!("Bad octet: {}", segment))?;
            let hi: u16 = segment[dash + 1..]
                .trim()
                .parse()
                .map_err(|_| format!("Bad octet: {}", segment))?;
            if lo > 255 || hi > 255 || hi < lo {
                return Err(format!("Out-of-range octet: {}", segment));
            }
            for v in lo..=hi {
                values.push(v as u8);
            }
        } else {
            let v: u16 = segment
                .parse()
                .map_err(|_| format!("Bad octet: {}", segment))?;
            if v > 255 {
                return Err(format!("Octet > 255: {}", segment));
            }
            values.push(v as u8);
        }
    }
    Ok(values)
}

fn parse_nmap(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = s.splitn(4, '.').collect();
    if parts.len() != 4 {
        return Err(format!("Expected 4 octets: {}", s));
    }
    let o1 = parse_octet_part(parts[0])?;
    let o2 = parse_octet_part(parts[1])?;
    let o3 = parse_octet_part(parts[2])?;
    let o4 = parse_octet_part(parts[3])?;

    let capacity = o1.len() * o2.len() * o3.len() * o4.len();
    if capacity > 4_000_000 {
        return Err(format!("Range too large: {} addresses", capacity));
    }

    let mut result = Vec::with_capacity(capacity);
    for &a in &o1 {
        for &b in &o2 {
            for &c in &o3 {
                for &d in &o4 {
                    result.push(Ipv4Addr::new(a, b, c, d));
                }
            }
        }
    }
    Ok(result)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(s: &str) -> Vec<Ipv4Addr> {
        parse_range(s).expect(s)
    }

    #[test]
    fn test_single_ip() {
        let v = ips("192.168.1.1");
        assert_eq!(v, vec!["192.168.1.1".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn test_cidr_24() {
        let v = ips("192.168.1.0/24");
        assert_eq!(v.len(), 256);
        assert_eq!(v[0], "192.168.1.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(v[255], "192.168.1.255".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_cidr_32() {
        let v = ips("10.0.0.1/32");
        assert_eq!(v, vec!["10.0.0.1".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn test_dash_range_full() {
        let v = ips("10.0.0.1-10.0.0.5");
        assert_eq!(v.len(), 5);
        assert_eq!(v[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(v[4], "10.0.0.5".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_nmap_last_octet_range() {
        let v = ips("10.0.0.1-5");
        assert_eq!(v.len(), 5);
        assert_eq!(v[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(v[4], "10.0.0.5".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_nmap_octet_list() {
        let v = ips("10.0.2,4.1");
        assert_eq!(v.len(), 2);
        assert!(v.contains(&"10.0.2.1".parse::<Ipv4Addr>().unwrap()));
        assert!(v.contains(&"10.0.4.1".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn test_nmap_complex() {
        // 192.168.0-10,100,199.1,254 → 1 * 1 * 13 * 2 = 26
        let v = ips("192.168.0-10,100,199.1,254");
        assert_eq!(v.len(), 26);
        assert!(v.contains(&"192.168.0.1".parse::<Ipv4Addr>().unwrap()));
        assert!(v.contains(&"192.168.10.254".parse::<Ipv4Addr>().unwrap()));
        assert!(v.contains(&"192.168.100.1".parse::<Ipv4Addr>().unwrap()));
        assert!(v.contains(&"192.168.199.254".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn test_comment_ignored() {
        assert_eq!(ips("# this is a comment"), Vec::<Ipv4Addr>::new());
        assert_eq!(ips("// also ignored"), Vec::<Ipv4Addr>::new());
        assert_eq!(ips("   "), Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn test_parse_all_ranges() {
        let text = "# comment\n192.168.1.1\n192.168.2.0/30\n";
        let v = parse_all_ranges(text);
        assert_eq!(v.len(), 5); // 1 + 4
    }
}

#[cfg(test)]
mod startup_range_tests {
    use super::*;
    #[test]
    fn cidr_accepts_spacing_around_the_slash() {
        for text in ["192.0.2.1 /24", "192.0.2.1/ 24", " 192.0.2.1 / 24 "] {
            let parsed = parse_all_ranges_checked(text).unwrap();
            assert_eq!(parsed.len(), 256);
            assert_eq!(parsed.first().unwrap().to_string(), "192.0.2.0");
            assert_eq!(parsed.last().unwrap().to_string(), "192.0.2.255");
        }
    }
    #[test]
    fn invalid_or_empty_input_is_an_explicit_error() {
        assert!(parse_all_ranges_checked("# comment only").is_err());
        let error = parse_all_ranges_checked("192.0.2.1\n192.0.2.2/99").unwrap_err();
        assert!(error.contains("line 2"));
    }
}
