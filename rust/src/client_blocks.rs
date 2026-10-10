use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Per-client domain blocks: a domain blocked only for specific client IPs.
/// Subdomain-aware, mirroring Blocklist semantics.
pub struct ClientBlocks {
    by_client: HashMap<IpAddr, HashSet<String>>,
}

impl ClientBlocks {
    pub fn new() -> Self {
        Self {
            by_client: HashMap::new(),
        }
    }

    pub fn contains(&self, client: IpAddr, domain: &str) -> bool {
        let Some(entries) = self.by_client.get(&client) else {
            return false;
        };
        let d = domain.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = d.split('.').collect();
        for start in 0..labels.len() {
            let sub: String = labels[start..].join(".");
            if entries.contains(&sub) {
                return true;
            }
        }
        false
    }

    /// Replace the full set. Entries are (client_ip, domain) pairs; malformed
    /// IPs are skipped.
    pub fn load(&mut self, entries: Vec<(String, String)>) {
        let mut map: HashMap<IpAddr, HashSet<String>> = HashMap::new();
        for (ip, domain) in entries {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                map.entry(addr)
                    .or_default()
                    .insert(domain.trim_end_matches('.').to_lowercase());
            }
        }
        self.by_client = map;
    }

    pub fn len(&self) -> usize {
        self.by_client.values().map(|s| s.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_blocks_nothing() {
        assert!(!ClientBlocks::new().contains(ip("192.168.1.1"), "ads.com"));
    }

    #[test]
    fn blocks_only_for_matching_client() {
        let mut c = ClientBlocks::new();
        c.load(vec![("192.168.1.1".into(), "ads.com".into())]);
        assert!(c.contains(ip("192.168.1.1"), "ads.com"));
        assert!(!c.contains(ip("192.168.1.2"), "ads.com")); // different client
    }

    #[test]
    fn subdomain_matches_client_entry() {
        let mut c = ClientBlocks::new();
        c.load(vec![("10.0.0.5".into(), "example.com".into())]);
        assert!(c.contains(ip("10.0.0.5"), "tracker.example.com"));
    }

    #[test]
    fn case_insensitive_dot_stripped() {
        let mut c = ClientBlocks::new();
        c.load(vec![("10.0.0.5".into(), "Ads.COM".into())]);
        assert!(c.contains(ip("10.0.0.5"), "ADS.com."));
    }

    #[test]
    fn unrelated_domain_not_blocked() {
        let mut c = ClientBlocks::new();
        c.load(vec![("10.0.0.5".into(), "ads.com".into())]);
        assert!(!c.contains(ip("10.0.0.5"), "example.org"));
    }

    #[test]
    fn load_replaces_and_skips_bad_ip() {
        let mut c = ClientBlocks::new();
        c.load(vec![("10.0.0.5".into(), "a.com".into())]);
        c.load(vec![
            ("10.0.0.6".into(), "b.com".into()),
            ("not-an-ip".into(), "c.com".into()),
        ]);
        assert!(!c.contains(ip("10.0.0.5"), "a.com")); // replaced
        assert!(c.contains(ip("10.0.0.6"), "b.com"));
        assert_eq!(c.len(), 1); // bad ip skipped
    }
}
