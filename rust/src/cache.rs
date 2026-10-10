use std::collections::HashMap;
use std::time::{Duration, Instant};

struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

pub struct Cache {
    entries: HashMap<String, CacheEntry>,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            min_ttl: 0,
            max_ttl: u32::MAX,
        }
    }

    pub fn lookup(&self, key: &str) -> Option<(Vec<u8>, u32)> {
        self.entries.get(key).and_then(|entry| {
            let now = Instant::now();
            if now < entry.expires_at {
                let remaining = (entry.expires_at - now).as_secs() as u32;
                Some((entry.response.clone(), remaining.max(1)))
            } else {
                None
            }
        })
    }

    /// Apply the ConfigMap `cache` block. Every insert (local or propagated from
    /// a peer) is clamped to [min_ttl, max_ttl].
    pub fn set_limits(&mut self, max_entries: usize, min_ttl: u32, max_ttl: u32) {
        self.max_entries = max_entries;
        self.min_ttl = min_ttl;
        self.max_ttl = max_ttl.max(min_ttl);
        if self.entries.len() > max_entries {
            let now = Instant::now();
            self.entries.retain(|_, e| now < e.expires_at);
            while self.entries.len() > max_entries {
                if let Some(key) = self.entries.keys().next().cloned() {
                    self.entries.remove(&key);
                }
            }
        }
    }

    pub fn insert(&mut self, key: String, response: Vec<u8>, ttl: u32) {
        let ttl = ttl.clamp(self.min_ttl, self.max_ttl);
        self.insert_exact(key, response, ttl);
    }

    pub fn insert_exact(&mut self, key: String, response: Vec<u8>, ttl: u32) {
        if self.max_entries == 0 || ttl == 0 {
            return;
        }
        let ttl = ttl.min(self.max_ttl);
        if self.entries.len() >= self.max_entries {
            self.entries.retain(|_, e| Instant::now() < e.expires_at);
            if self.entries.len() >= self.max_entries {
                return;
            }
        }
        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);
        self.entries.insert(
            key,
            CacheEntry {
                response,
                expires_at,
            },
        );
    }

    /// Evict every cached qtype for a domain. Keys are `domain:qtype`,
    /// so match the `domain:` prefix.
    pub fn evict_domain(&mut self, domain: &str) -> usize {
        let domain = domain.to_lowercase();
        let prefix = format!("{}:", domain);
        let routed = format!("|{}:", domain);
        let before = self.entries.len();
        self.entries
            .retain(|k, _| !k.starts_with(&prefix) && !k.contains(&routed));
        before - self.entries.len()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_returns_none() {
        let c = Cache::new(100);
        assert_eq!(c.lookup("example.com:1"), None);
    }

    #[test]
    fn insert_and_lookup_returns_entry() {
        let mut c = Cache::new(100);
        c.insert("example.com:1".into(), vec![1, 2, 3], 3600);
        let result = c.lookup("example.com:1");
        assert!(result.is_some());
        let (data, ttl) = result.unwrap();
        assert_eq!(data, vec![1, 2, 3]);
        assert!(ttl > 0 && ttl <= 3600);
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut c = Cache::new(100);
        c.insert("short-lived:1".into(), vec![4, 5, 6], 0);
        // TTL 0 means expires immediately
        assert_eq!(c.lookup("short-lived:1"), None);
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut c = Cache::new(100);
        c.insert("a:1".into(), vec![1], 3600);
        c.insert("b:1".into(), vec![2], 3600);
        c.clear();
        assert_eq!(c.lookup("a:1"), None);
        assert_eq!(c.lookup("b:1"), None);
    }

    #[test]
    fn evict_domain_removes_all_qtypes() {
        let mut c = Cache::new(100);
        c.insert("home.hybridoptix.net:1".into(), vec![1], 3600);
        c.insert("home.hybridoptix.net:28".into(), vec![2], 3600);
        c.insert("other.net:1".into(), vec![3], 3600);
        let n = c.evict_domain("home.hybridoptix.net");
        assert_eq!(n, 2);
        assert_eq!(c.lookup("home.hybridoptix.net:1"), None);
        assert_eq!(c.lookup("home.hybridoptix.net:28"), None);
        assert!(c.lookup("other.net:1").is_some());
    }

    #[test]
    fn evict_domain_is_case_insensitive_and_prefix_safe() {
        let mut c = Cache::new(100);
        c.insert("home.net:1".into(), vec![1], 3600);
        c.insert("home.net.evil.com:1".into(), vec![2], 3600); // must NOT match
        assert_eq!(c.evict_domain("HOME.NET"), 1);
        assert!(c.lookup("home.net.evil.com:1").is_some());
    }

    #[test]
    fn different_keys_are_independent() {
        let mut c = Cache::new(100);
        c.insert("alpha:1".into(), vec![10], 3600);
        c.insert("beta:28".into(), vec![20], 3600);
        let (data, _) = c.lookup("alpha:1").unwrap();
        assert_eq!(data, vec![10]);
        let (data, _) = c.lookup("beta:28").unwrap();
        assert_eq!(data, vec![20]);
    }

    #[test]
    fn insert_at_capacity_drops_oldest_expired() {
        let mut c = Cache::new(2);
        c.insert("a:1".into(), vec![1], 3600);
        c.insert("b:1".into(), vec![2], 0); // expired
        c.insert("c:1".into(), vec![3], 3600); // triggers eviction of expired
                                               // b was expired and evicted; a and c fit within max_entries
        assert!(c.lookup("a:1").is_some());
        assert!(c.lookup("c:1").is_some());
    }

    #[test]
    fn ttl_is_capped_at_max_ttl() {
        let mut c = Cache::new(100);
        c.set_limits(100, 60, 3600);
        c.insert("week:1".into(), vec![1], 604_800);
        let (_, ttl) = c.lookup("week:1").unwrap();
        assert!(ttl <= 3600, "cached for {ttl}s");
    }

    #[test]
    fn ttl_is_raised_to_min_ttl() {
        let mut c = Cache::new(100);
        c.set_limits(100, 60, 3600);
        c.insert("short:1".into(), vec![1], 5);
        let (_, ttl) = c.lookup("short:1").unwrap();
        assert!(ttl >= 59, "cached for only {ttl}s");
    }

    #[test]
    fn max_entries_limit_is_applied() {
        let mut c = Cache::new(100);
        c.set_limits(2, 0, 3600);
        c.insert("a:1".into(), vec![1], 3600);
        c.insert("b:1".into(), vec![2], 3600);
        c.insert("c:1".into(), vec![3], 3600);
        assert_eq!(c.lookup("c:1"), None);
    }

    #[test]
    fn insert_at_capacity_with_no_expired_drops_new() {
        let mut c = Cache::new(1);
        c.insert("a:1".into(), vec![1], 3600);
        c.insert("b:1".into(), vec![2], 3600); // still full, no expired entries
        assert!(c.lookup("a:1").is_some());
        assert_eq!(c.lookup("b:1"), None);
    }
}
