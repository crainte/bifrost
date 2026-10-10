use std::collections::{BTreeMap, HashMap, HashSet};

/// Entries prefixed with this are list-local exceptions (adblock `@@` rules):
/// they unblock their subtree for the list that declared them, never for others.
const EXCEPTION_PREFIX: &str = "@@";

#[derive(Default)]
struct ListSet {
    blocked: HashSet<Box<str>>,
    exceptions: HashSet<Box<str>>,
}

impl ListSet {
    fn extend(&mut self, domains: Vec<String>) {
        for raw in domains {
            match raw.strip_prefix(EXCEPTION_PREFIX) {
                Some(d) => self.exceptions.insert(normalize(d)),
                None => self.blocked.insert(normalize(&raw)),
            };
        }
    }

    fn excepts(&self, suffixes: &[&str]) -> bool {
        !self.exceptions.is_empty() && suffixes.iter().any(|s| self.exceptions.contains(*s))
    }
}

fn normalize(domain: &str) -> Box<str> {
    domain
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .into_boxed_str()
}

/// Every suffix of `domain` on a label boundary, most specific first:
/// `a.b.c` -> [`a.b.c`, `b.c`, `c`]. Borrowed slices, no per-suffix allocation.
fn suffixes(domain: &str) -> Vec<&str> {
    let mut out = vec![domain];
    out.extend(domain.match_indices('.').map(|(i, _)| &domain[i + 1..]));
    out
}

pub struct Blocklist {
    /// BTreeMap, not HashMap: when several lists match at the same specificity,
    /// iteration order decides attribution, and it must not change between calls.
    lists: BTreeMap<String, ListSet>,
    /// Lists being rebuilt in batches; swapped in whole by `commit`.
    staging: HashMap<String, ListSet>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            lists: BTreeMap::new(),
            staging: HashMap::new(),
        }
    }

    /// Most specific matching entry wins; ties go to the alphabetically-first
    /// list id. A list whose own exception covers the name does not match.
    pub fn contains(&self, domain: &str) -> Option<&str> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return None;
        }
        let sfx = suffixes(&d);
        for s in &sfx {
            for (list_id, set) in &self.lists {
                if set.blocked.contains(*s) && !set.excepts(&sfx) {
                    return Some(list_id);
                }
            }
        }
        None
    }

    /// Append to the list being staged if `begin` was called, else to the live list.
    pub fn load(&mut self, list_id: &str, domains: Vec<String>) {
        match self.staging.get_mut(list_id) {
            Some(staged) => staged.extend(domains),
            None => self
                .lists
                .entry(list_id.to_string())
                .or_default()
                .extend(domains),
        }
    }

    /// Start rebuilding `list_id` off to the side; the live copy keeps serving.
    pub fn begin(&mut self, list_id: &str) {
        self.staging.insert(list_id.to_string(), ListSet::default());
    }

    /// Replace the live list with the staged one in a single step.
    pub fn commit(&mut self, list_id: &str) {
        if let Some(mut staged) = self.staging.remove(list_id) {
            staged.blocked.shrink_to_fit();
            staged.exceptions.shrink_to_fit();
            self.lists.insert(list_id.to_string(), staged);
        }
    }

    pub fn clear(&mut self) {
        self.lists.clear();
        self.staging.clear();
    }

    pub fn clear_list(&mut self, list_id: &str) {
        self.lists.remove(list_id);
        self.staging.remove(list_id);
    }

    pub fn len_for_list(&self, list_id: &str) -> usize {
        self.lists
            .get(list_id)
            .map(|s| s.blocked.len())
            .unwrap_or(0)
    }

    pub fn list_count(&self) -> usize {
        self.lists.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blocklist_returns_none() {
        let b = Blocklist::new();
        assert_eq!(b.contains("example.com"), None);
        assert_eq!(b.contains(""), None);
    }

    #[test]
    fn exact_match_returns_list_id() {
        let mut b = Blocklist::new();
        b.load("test-list", vec!["example.com".to_string()]);
        assert_eq!(b.contains("example.com"), Some("test-list"));
    }

    #[test]
    fn subdomain_matches_parent_list_entry() {
        let mut b = Blocklist::new();
        b.load("test-list", vec!["example.com".to_string()]);
        assert_eq!(b.contains("sub.example.com"), Some("test-list"));
        assert_eq!(b.contains("deep.sub.example.com"), Some("test-list"));
    }

    #[test]
    fn different_tld_does_not_match() {
        let mut b = Blocklist::new();
        b.load("test-list", vec!["example.com".to_string()]);
        assert_eq!(b.contains("example.net"), None);
    }

    #[test]
    fn unrelated_domain_returns_none() {
        let mut b = Blocklist::new();
        b.load("test-list", vec!["ads.example.com".to_string()]);
        assert_eq!(b.contains("safe.org"), None);
    }

    #[test]
    fn trailing_dot_is_stripped() {
        let mut b = Blocklist::new();
        b.load("test-list", vec!["example.com".to_string()]);
        assert_eq!(b.contains("example.com."), Some("test-list"));
    }

    #[test]
    fn multiple_lists_are_independent() {
        let mut b = Blocklist::new();
        b.load("list-a", vec!["foo.com".to_string()]);
        b.load("list-b", vec!["bar.com".to_string()]);
        assert_eq!(b.contains("foo.com"), Some("list-a"));
        assert_eq!(b.contains("bar.com"), Some("list-b"));
        assert_eq!(b.contains("baz.com"), None);
    }

    #[test]
    fn clear_removes_all_lists() {
        let mut b = Blocklist::new();
        b.load("a", vec!["x.com".to_string()]);
        b.load("b", vec!["y.com".to_string()]);
        b.clear();
        assert_eq!(b.contains("x.com"), None);
        assert_eq!(b.contains("y.com"), None);
        assert_eq!(b.list_count(), 0);
    }

    #[test]
    fn clear_list_removes_only_that_list() {
        let mut b = Blocklist::new();
        b.load("a", vec!["foo.com".to_string()]);
        b.load("b", vec!["bar.com".to_string()]);
        b.clear_list("a");
        assert_eq!(b.contains("foo.com"), None);
        assert_eq!(b.contains("bar.com"), Some("b"));
        assert_eq!(b.list_count(), 1);
    }

    #[test]
    fn len_for_list_returns_correct_count() {
        let mut b = Blocklist::new();
        assert_eq!(b.len_for_list("nonexistent"), 0);
        b.load("a", vec!["x.com".to_string(), "y.com".to_string()]);
        assert_eq!(b.len_for_list("a"), 2);
    }

    #[test]
    fn matching_ignores_query_case() {
        let mut b = Blocklist::new();
        b.load("l", vec!["ads.example.com".into()]);
        assert_eq!(b.contains("ADS.example.com"), Some("l"));
        assert_eq!(b.contains("aDs.ExAmPlE.cOm."), Some("l"));
        assert_eq!(b.contains("Sub.ADS.example.com"), Some("l"));
    }

    #[test]
    fn loaded_entries_are_case_normalized() {
        let mut b = Blocklist::new();
        b.load("l", vec!["Tracker.Example.NET.".into()]);
        assert_eq!(b.contains("tracker.example.net"), Some("l"));
    }

    #[test]
    fn attribution_is_deterministic_when_lists_overlap() {
        // Same specificity in several lists: the alphabetically-first list id
        // wins, every time, so per-list block metrics are stable.
        for _ in 0..50 {
            let mut b = Blocklist::new();
            b.load("zeta", vec!["ads.com".into()]);
            b.load("alpha", vec!["ads.com".into()]);
            b.load("mid", vec!["ads.com".into()]);
            assert_eq!(b.contains("ads.com"), Some("alpha"));
        }
    }

    #[test]
    fn most_specific_entry_wins_attribution() {
        let mut b = Blocklist::new();
        b.load("alpha", vec!["example.com".into()]);
        b.load("zeta", vec!["ads.example.com".into()]);
        assert_eq!(b.contains("ads.example.com"), Some("zeta"));
    }

    #[test]
    fn exception_entry_unblocks_subtree_within_its_own_list() {
        let mut b = Blocklist::new();
        b.load("l", vec!["ads.com".into(), "@@safe.ads.com".into()]);
        assert_eq!(b.contains("ads.com"), Some("l"));
        assert_eq!(b.contains("x.ads.com"), Some("l"));
        assert_eq!(b.contains("safe.ads.com"), None);
        assert_eq!(b.contains("deep.safe.ads.com"), None);
        assert_eq!(b.len_for_list("l"), 1);
    }

    #[test]
    fn exception_does_not_override_other_lists() {
        let mut b = Blocklist::new();
        b.load("browser", vec!["ads.com".into(), "@@safe.ads.com".into()]);
        b.load("security", vec!["safe.ads.com".into()]);
        assert_eq!(b.contains("safe.ads.com"), Some("security"));
    }

    #[test]
    fn staged_list_is_invisible_until_commit_then_replaces_atomically() {
        let mut b = Blocklist::new();
        b.load("l", vec!["old.com".into()]);
        b.begin("l");
        b.load("l", vec!["new.com".into()]);
        b.load("l", vec!["newer.com".into()]);
        // Mid-reload the live list is untouched: nothing is briefly unblocked.
        assert_eq!(b.contains("old.com"), Some("l"));
        assert_eq!(b.contains("new.com"), None);
        b.commit("l");
        assert_eq!(b.contains("old.com"), None);
        assert_eq!(b.contains("new.com"), Some("l"));
        assert_eq!(b.contains("newer.com"), Some("l"));
    }

    #[test]
    fn commit_without_begin_is_a_noop() {
        let mut b = Blocklist::new();
        b.load("l", vec!["a.com".into()]);
        b.commit("l");
        assert_eq!(b.contains("a.com"), Some("l"));
    }

    #[test]
    fn list_count_reflects_number_of_lists() {
        let mut b = Blocklist::new();
        assert_eq!(b.list_count(), 0);
        b.load("a", vec![]);
        assert_eq!(b.list_count(), 1);
        b.load("b", vec![]);
        assert_eq!(b.list_count(), 2);
    }
}
