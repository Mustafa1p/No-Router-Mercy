use crate::models::FilterRule;

/// Returns true if all filter rules pass (none triggered).
/// A triggered rule means the device should be filtered out (stop processing).
pub fn check_filters(rules: &[FilterRule], body: &str, server: &str, realm: &str) -> bool {
    for rule in rules {
        let haystack = match rule.place.as_str() {
            "body" => body,
            "serv" => server,
            "relm" => realm,
            _ => continue,
        };
        let triggered = match rule.mode.as_str() {
            "eq" => haystack.eq_ignore_ascii_case(&rule.pattern),
            "neq" => !haystack.eq_ignore_ascii_case(&rule.pattern),
            "cnt" => haystack
                .to_ascii_lowercase()
                .contains(&rule.pattern.to_ascii_lowercase()),
            "ncnt" => !haystack
                .to_ascii_lowercase()
                .contains(&rule.pattern.to_ascii_lowercase()),
            _ => false,
        };
        if triggered {
            return false; // filter triggered → skip device
        }
    }
    true
}

/// Parse filter.txt into FilterRule list.
/// Format: place<TAB>mode<TAB>pattern  (one per line)
pub fn parse_filter_rules(content: &str) -> Vec<FilterRule> {
    let mut rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() == 3 {
            rules.push(FilterRule {
                place: parts[0].to_string(),
                mode: parts[1].to_string(),
                pattern: parts[2].to_string(),
            });
        }
    }
    rules
}

pub fn serialize_filter_rules(rules: &[FilterRule]) -> String {
    rules
        .iter()
        .map(|r| format!("{}\t{}\t{}", r.place, r.mode, r.pattern))
        .collect::<Vec<_>>()
        .join("\n")
}
