/// Load credential pairs from a file in the format:
///   username<TAB>password
///   Lines not containing exactly one tab are ignored.
///   `<empty>` is the special token for an empty string.
pub fn load_credentials(path: &str) -> Vec<(String, String)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    parse_credentials(&content)
}

pub fn parse_credentials(content: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in content.lines() {
        // must contain exactly one tab
        let mut parts = line.splitn(2, '\t');
        let user = match parts.next() {
            Some(u) => u.trim(),
            None => continue,
        };
        let pass = match parts.next() {
            Some(p) => p.trim(),
            None => continue,
        };
        let user = if user == "<empty>" { "" } else { user };
        let pass = if pass == "<empty>" { "" } else { pass };
        pairs.push((user.to_string(), pass.to_string()));
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let content = "admin\tadmin\nroot\t\n# ignored\n\t<empty>\n<empty>\t<empty>";
        let pairs = parse_credentials(content);
        assert_eq!(pairs[0], ("admin".into(), "admin".into()));
        assert_eq!(pairs[1], ("root".into(), "".into()));
        assert_eq!(pairs[2], ("".into(), "".into()));
        assert_eq!(pairs[3], ("".into(), "".into()));
    }
}
