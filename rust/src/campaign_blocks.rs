use std::collections::HashMap;
use std::net::IpAddr;

/// One explicit campaign block (see the threat-campaign-blocking spec).
///
/// A *family* is `{n}.<parent>`: the first label is enumerated
/// (`^[0-9]+x*$`) and everything after it is exactly `parent`.
/// A *marker* is `<label>.*.<tld>`: the first label is exactly `label`, the
/// last is `tld`, and there are at least three labels (so `447.site` is out
/// but `447.sub.alpha.site` is in). Neither extends to parents, lookalike
/// labels or other TLDs. `client` of None applies to every client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub shape: Shape,
    pub client: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    Family { parent: String },
    Marker { tld: String, label: String },
}

/// `(rule id, client scope)` pairs sharing one index key, sorted by id.
type Scoped = Vec<(i64, Option<IpAddr>)>;

/// Immutable-by-replacement rule set, indexed so a DNS query costs a couple of
/// hash lookups and never scans the rules or the query history.
#[derive(Default)]
pub struct CampaignBlocks {
    families: HashMap<String, Scoped>,
    markers: HashMap<(String, String), Scoped>,
    count: usize,
}

impl CampaignBlocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a set from rules; any malformed rule rejects the WHOLE set, so a
    /// bad push can never leave a partially enforced policy behind.
    pub fn compile(mut rules: Vec<Rule>) -> Result<Self, String> {
        rules.sort_by_key(|r| r.id);
        let mut set = Self::default();
        for rule in rules {
            match &rule.shape {
                Shape::Family { parent } => {
                    if !valid_parent(parent) {
                        return Err(format!(
                            "rule {}: invalid family parent {parent:?}",
                            rule.id
                        ));
                    }
                    set.families
                        .entry(parent.clone())
                        .or_default()
                        .push((rule.id, rule.client));
                }
                Shape::Marker { tld, label } => {
                    if !valid_tld(tld) {
                        return Err(format!("rule {}: invalid marker tld {tld:?}", rule.id));
                    }
                    if !enumerated(label) {
                        return Err(format!("rule {}: invalid marker label {label:?}", rule.id));
                    }
                    set.markers
                        .entry((tld.clone(), label.clone()))
                        .or_default()
                        .push((rule.id, rule.client));
                }
            }
            set.count += 1;
        }
        Ok(set)
    }

    /// The id of the first rule (lowest id) that blocks `domain` for `client`.
    pub fn matches(&self, client: IpAddr, domain: &str) -> Option<i64> {
        if self.count == 0 {
            return None;
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let (first, rest) = d.split_once('.')?;
        let in_scope = |rules: &Scoped| {
            rules
                .iter()
                .find(|(_, c)| c.is_none_or(|c| c == client))
                .map(|(id, _)| *id)
        };
        let family = if enumerated(first) {
            self.families.get(rest).and_then(in_scope)
        } else {
            None
        };
        // Marker: at least three labels, i.e. something between first and tld.
        let marker = rest.rsplit_once('.').and_then(|(_, tld)| {
            self.markers
                .get(&(tld.to_string(), first.to_string()))
                .and_then(in_scope)
        });
        match (family, marker) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

/// `^[0-9]+x*$`, at most 63 bytes: the enumerated first label of a campaign.
fn enumerated(label: &str) -> bool {
    let digits = label.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && label.len() <= 63 && label[digits..].bytes().all(|b| b == b'x')
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A normalised (lowercase, no trailing dot) name of two or more labels.
fn valid_parent(p: &str) -> bool {
    p.len() <= 253 && p.split('.').count() >= 2 && p.split('.').all(valid_label)
}

/// One lowercase label, `^[a-z0-9-]{2,63}$`.
fn valid_tld(t: &str) -> bool {
    (2..=63).contains(&t.len())
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Parse the wire form of a rule from the `apply_campaign_blocks` message.
pub fn rule_from_json(v: &serde_json::Value) -> Result<Rule, String> {
    let id = v["id"].as_i64().ok_or("rule without id")?;
    let text = |k: &str| v[k].as_str().map(str::to_string);
    let shape = match v["kind"].as_str() {
        Some("family") => Shape::Family {
            parent: text("parent").ok_or("family rule without parent")?,
        },
        Some("marker") => Shape::Marker {
            tld: text("tld").ok_or("marker rule without tld")?,
            label: text("leading_label").ok_or("marker rule without leading_label")?,
        },
        other => return Err(format!("unknown rule kind {other:?}")),
    };
    let client = match v.get("client_ip") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(
            s.parse::<IpAddr>()
                .map_err(|_| format!("rule {id}: invalid client_ip {s:?}"))?,
        ),
        other => return Err(format!("rule {id}: invalid client_ip {other:?}")),
    };
    Ok(Rule { id, shape, client })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn family(id: i64, parent: &str, client: Option<&str>) -> Rule {
        Rule {
            id,
            shape: Shape::Family {
                parent: parent.into(),
            },
            client: client.map(ip),
        }
    }

    fn marker(id: i64, label: &str, tld: &str, client: Option<&str>) -> Rule {
        Rule {
            id,
            shape: Shape::Marker {
                tld: tld.into(),
                label: label.into(),
            },
            client: client.map(ip),
        }
    }

    /// The vectors shared with the Erlang SQL matcher (bifrost_campaign_block_SUITE).
    #[test]
    fn shared_vectors_match_exactly() {
        let raw = include_str!("../../erlang/apps/bifrost/test/campaign_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let rule = rule_from_json(&json!({
                "id": 1,
                "kind": case["rule"]["kind"],
                "parent": case["rule"]["parent"],
                "tld": case["rule"]["tld"],
                "leading_label": case["rule"]["leading_label"],
                "client_ip": null,
            }))
            .unwrap();
            let set = CampaignBlocks::compile(vec![rule]).unwrap();
            let c = ip("192.168.1.10");
            for name in case["match"].as_array().unwrap() {
                let name = name.as_str().unwrap();
                assert_eq!(set.matches(c, name), Some(1), "{name} must match {case}");
            }
            for name in case["no_match"].as_array().unwrap() {
                let name = name.as_str().unwrap();
                assert_eq!(set.matches(c, name), None, "{name} must not match {case}");
            }
        }
    }

    #[test]
    fn spec_family_boundary() {
        let set = CampaignBlocks::compile(vec![family(1, "stg.example.com", None)]).unwrap();
        let c = ip("10.0.0.1");
        for hit in ["3.stg.example.com", "3x.stg.example.com"] {
            assert_eq!(set.matches(c, hit), Some(1), "{hit}");
        }
        for miss in [
            "abc.stg.example.com",
            "3.other.example.com",
            "stg.example.com",
            "3.stg.example.com.evil",
        ] {
            assert_eq!(set.matches(c, miss), None, "{miss}");
        }
    }

    #[test]
    fn spec_marker_boundary() {
        let set = CampaignBlocks::compile(vec![marker(2, "447", "site", None)]).unwrap();
        let c = ip("10.0.0.1");
        for hit in ["447.alpha.site", "447.sub.alpha.site"] {
            assert_eq!(set.matches(c, hit), Some(2), "{hit}");
        }
        for miss in ["447.site", "447.alpha.com", "447x.alpha.site"] {
            assert_eq!(set.matches(c, miss), None, "{miss}");
        }
    }

    #[test]
    fn matches_names_that_were_never_queried() {
        // Nothing here knows about query history: the rule is the pattern.
        let set = CampaignBlocks::compile(vec![family(1, "stg.example.com", None)]).unwrap();
        assert_eq!(
            set.matches(ip("10.0.0.1"), "98765.stg.example.com"),
            Some(1)
        );
    }

    #[test]
    fn client_scope_applies_only_to_that_client() {
        let set =
            CampaignBlocks::compile(vec![family(1, "stg.example.com", Some("10.0.0.5"))]).unwrap();
        assert_eq!(set.matches(ip("10.0.0.5"), "3.stg.example.com"), Some(1));
        assert_eq!(set.matches(ip("10.0.0.6"), "3.stg.example.com"), None);
    }

    #[test]
    fn global_and_client_rules_coexist_lowest_id_wins() {
        let set = CampaignBlocks::compile(vec![
            family(9, "stg.example.com", None),
            family(4, "stg.example.com", Some("10.0.0.5")),
        ])
        .unwrap();
        assert_eq!(set.matches(ip("10.0.0.5"), "1.stg.example.com"), Some(4));
        assert_eq!(set.matches(ip("10.0.0.6"), "1.stg.example.com"), Some(9));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn empty_set_blocks_nothing() {
        assert_eq!(
            CampaignBlocks::new().matches(ip("10.0.0.1"), "3.stg.example.com"),
            None
        );
    }

    #[test]
    fn mixed_case_and_trailing_dot_are_normalised() {
        let set = CampaignBlocks::compile(vec![marker(1, "447", "site", None)]).unwrap();
        assert_eq!(set.matches(ip("10.0.0.1"), "447.ALPHA.Site."), Some(1));
    }

    #[test]
    fn malformed_rule_rejects_the_whole_set() {
        let good = family(1, "stg.example.com", None);
        for bad in [
            family(2, "com", None),              // parent needs 2+ labels
            family(3, "", None),                 // empty
            family(4, "bad..example.com", None), // empty label
            family(5, "stg.example.com.", None), // not normalised
            family(6, "STG.example.com", None),  // not lowercase
            marker(7, "abc", "site", None),      // label not enumerated
            marker(8, "447", "", None),          // empty tld
            marker(9, "447", "a.site", None),    // tld is one label
            marker(10, "447", "SITE", None),     // not lowercase
        ] {
            assert!(
                CampaignBlocks::compile(vec![good.clone(), bad.clone()]).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn parses_wire_rules() {
        let f = rule_from_json(
            &json!({"id": 7, "kind": "family", "parent": "stg.example.com",
            "tld": "com", "leading_label": null, "client_ip": null}),
        )
        .unwrap();
        assert_eq!(f, family(7, "stg.example.com", None));
        let m = rule_from_json(&json!({"id": 8, "kind": "marker", "parent": null,
            "tld": "site", "leading_label": "447", "client_ip": "10.0.0.9"}))
        .unwrap();
        assert_eq!(m, marker(8, "447", "site", Some("10.0.0.9")));
    }

    #[test]
    fn rejects_malformed_client_scope_instead_of_making_rule_global() {
        // The wire rule always includes client_ip: null means global, a string
        // means one client. Other values (including omission) are not global.
        for scope in [json!(123), json!(false), json!([]), json!({})] {
            let raw = json!({"id": 11, "kind": "family", "parent": "stg.example.com",
                "client_ip": scope});
            assert!(rule_from_json(&raw).is_err(), "{raw} must be rejected");
        }
        let missing = json!({"id": 11, "kind": "family", "parent": "stg.example.com"});
        assert!(
            rule_from_json(&missing).is_err(),
            "{missing} must be rejected"
        );
    }

    #[test]
    fn rejects_unparseable_wire_rules() {
        for bad in [
            json!({"kind": "family", "parent": "a.b.com"}), // no id
            json!({"id": 1, "kind": "regex", "parent": "a.b.com"}), // unknown kind
            json!({"id": 1, "kind": "family"}),             // no parent
            json!({"id": 1, "kind": "marker", "tld": "site"}), // no label
            json!({"id": 1, "kind": "family", "parent": "a.b.com", "client_ip": "nope"}),
        ] {
            assert!(rule_from_json(&bad).is_err(), "{bad}");
        }
    }
}
