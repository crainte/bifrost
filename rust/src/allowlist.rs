use std::collections::HashSet;

/// Domains that bypass blocklist matching. Subdomain-aware, mirroring
/// Blocklist::contains — an entry `example.com` allows `ads.example.com`.
pub struct Allowlist {
    entries: HashSet<String>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = d.split('.').collect();
        for start in 0..labels.len() {
            let sub: String = labels[start..].join(".");
            if self.entries.contains(&sub) {
                return true;
            }
        }
        false
    }

    /// Replace the full set (allowlist is small and fully pushed by Erlang).
    pub fn load(&mut self, domains: Vec<String>) {
        self.entries = domains
            .into_iter()
            .map(|d| d.trim_end_matches('.').to_lowercase())
            .collect();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allows_nothing() {
        assert!(!Allowlist::new().contains("github.com"));
    }

    #[test]
    fn exact_match() {
        let mut a = Allowlist::new();
        a.load(vec!["github.com".into()]);
        assert!(a.contains("github.com"));
    }

    #[test]
    fn subdomain_matches_parent_entry() {
        let mut a = Allowlist::new();
        a.load(vec!["example.com".into()]);
        assert!(a.contains("ads.example.com"));
    }

    #[test]
    fn unrelated_domain_not_allowed() {
        let mut a = Allowlist::new();
        a.load(vec!["example.com".into()]);
        assert!(!a.contains("example.org"));
    }

    #[test]
    fn case_insensitive_and_dot_stripped() {
        let mut a = Allowlist::new();
        a.load(vec!["GitHub.com".into()]);
        assert!(a.contains("GITHUB.COM."));
    }

    #[test]
    fn load_replaces_previous() {
        let mut a = Allowlist::new();
        a.load(vec!["a.com".into()]);
        a.load(vec!["b.com".into()]);
        assert!(!a.contains("a.com"));
        assert!(a.contains("b.com"));
        assert_eq!(a.len(), 1);
    }
}
