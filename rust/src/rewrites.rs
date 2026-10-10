use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Resolved target of a rewrite rule: a synthesized address record or a CNAME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    Cname(String),
}

impl Target {
    /// Parse a rewrite target string. A valid IP → address record;
    /// anything else is treated as a CNAME target (trailing dot stripped).
    fn parse(target: &str) -> Self {
        match IpAddr::from_str(target) {
            Ok(ip) => Target::Ip(ip),
            Err(_) => Target::Cname(target.trim_end_matches('.').to_string()),
        }
    }
}

pub struct Rewrites {
    rules: HashMap<String, Target>,
}

impl Rewrites {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    /// Exact-match lookup. Rewrites are authoritative for a single name,
    /// not a subtree — `nas.home` does not rewrite `x.nas.home`.
    pub fn lookup(&self, domain: &str) -> Option<&Target> {
        self.rules.get(&domain.trim_end_matches('.').to_lowercase())
    }

    /// Replace the full rule set (rewrites are a small, fully-pushed table).
    pub fn load(&mut self, entries: Vec<(String, String)>) {
        self.rules = entries
            .into_iter()
            .map(|(d, t)| (d.trim_end_matches('.').to_lowercase(), Target::parse(&t)))
            .collect();
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        assert_eq!(Rewrites::new().lookup("nas.home"), None);
    }

    #[test]
    fn ip_target_parsed_as_ip() {
        let mut r = Rewrites::new();
        r.load(vec![("nas.home".into(), "192.168.1.5".into())]);
        assert_eq!(
            r.lookup("nas.home"),
            Some(&Target::Ip("192.168.1.5".parse().unwrap()))
        );
    }

    #[test]
    fn v6_target_parsed_as_ip() {
        let mut r = Rewrites::new();
        r.load(vec![("nas.home".into(), "::1".into())]);
        assert_eq!(
            r.lookup("nas.home"),
            Some(&Target::Ip("::1".parse().unwrap()))
        );
    }

    #[test]
    fn non_ip_target_parsed_as_cname() {
        let mut r = Rewrites::new();
        r.load(vec![("www.home".into(), "server.home.".into())]);
        assert_eq!(
            r.lookup("www.home"),
            Some(&Target::Cname("server.home".into()))
        );
    }

    #[test]
    fn lookup_is_case_insensitive_and_dot_stripped() {
        let mut r = Rewrites::new();
        r.load(vec![("Nas.Home".into(), "192.168.1.5".into())]);
        assert!(r.lookup("NAS.HOME.").is_some());
    }

    #[test]
    fn exact_match_only_no_subtree() {
        let mut r = Rewrites::new();
        r.load(vec![("nas.home".into(), "192.168.1.5".into())]);
        assert_eq!(r.lookup("x.nas.home"), None);
    }

    #[test]
    fn load_replaces_previous_rules() {
        let mut r = Rewrites::new();
        r.load(vec![("a.home".into(), "1.1.1.1".into())]);
        r.load(vec![("b.home".into(), "2.2.2.2".into())]);
        assert_eq!(r.lookup("a.home"), None);
        assert!(r.lookup("b.home").is_some());
        assert_eq!(r.len(), 1);
    }
}
