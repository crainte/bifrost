use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::forwarder::{Forwarder, Strategy};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub primary: Vec<Endpoint>,
    pub fallback: Vec<Endpoint>,
    pub strategy: Strategy,
    pub timeout_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub domains: Vec<String>,
    pub primary: Vec<Endpoint>,
    pub fallback: Vec<Endpoint>,
    pub strategy: Strategy,
    pub timeout_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSettings {
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub max_entries: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockingSettings {
    pub mode: String,
    pub custom_ip: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseSettings {
    pub enrichment_enabled: bool,
    pub route_private_ptr: bool,
    pub resolvers: Vec<Endpoint>,
    pub positive_ttl_seconds: u32,
    pub negative_ttl_seconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub schema_version: u32,
    pub upstreams: Group,
    pub routes: Vec<Route>,
    pub cache: CacheSettings,
    pub blocking: BlockingSettings,
    pub reverse_dns: ReverseSettings,
    pub retention_months: u32,
}

pub struct CompiledSettings {
    pub routing: Routing,
    pub cache: CacheSettings,
    pub block_mode: crate::BlockMode,
}

impl Settings {
    pub fn compile(self) -> Result<CompiledSettings, String> {
        if self.schema_version != 1
            || self.cache.min_ttl > self.cache.max_ttl
            || self.cache.min_ttl > 86400
            || self.cache.max_ttl > 604800
            || self.cache.max_entries > 1000000
            || self.retention_months > 1200
            || !(1..=604800).contains(&self.reverse_dns.positive_ttl_seconds)
            || !(1..=86400).contains(&self.reverse_dns.negative_ttl_seconds)
            || self.reverse_dns.resolvers.len() > 8
        {
            return Err("invalid DNS settings limits".into());
        }
        let mut endpoints = std::collections::HashSet::new();
        for e in &self.reverse_dns.resolvers {
            if !endpoints.insert(e.socket()?) {
                return Err("duplicate private resolver".into());
            }
        }
        if (self.reverse_dns.enrichment_enabled || self.reverse_dns.route_private_ptr)
            && endpoints.is_empty()
        {
            return Err("private resolver required".into());
        }
        let block_mode = match self.blocking.mode.as_str() {
            "custom_ip" => crate::BlockMode::CustomIp(
                self.blocking
                    .custom_ip
                    .parse()
                    .map_err(|_| "invalid custom IP")?,
            ),
            mode if self.blocking.custom_ip.is_empty() => match mode {
                "zero_ip" => crate::BlockMode::ZeroIp,
                "nxdomain" => crate::BlockMode::NXDomain,
                "refused" => crate::BlockMode::Refused,
                _ => return Err("invalid blocking mode".into()),
            },
            _ => return Err("custom IP requires custom_ip mode".into()),
        };
        let mut routing = Routing::compile(&self.upstreams, self.routes)?;
        if self.reverse_dns.route_private_ptr {
            routing.private = Some(
                Group {
                    primary: self.reverse_dns.resolvers,
                    fallback: vec![],
                    strategy: Strategy::Sequential,
                    timeout_ms: self.upstreams.timeout_ms,
                    deadline_ms: self.upstreams.deadline_ms,
                }
                .compile()?,
            );
        }
        Ok(CompiledSettings {
            routing,
            cache: self.cache,
            block_mode,
        })
    }
}

pub struct Routing {
    pub default: Arc<Forwarder>,
    routes: HashMap<String, Arc<Forwarder>>,
    pub private: Option<Arc<Forwarder>>,
}

pub enum Decision {
    Forward(Arc<Forwarder>),
    PrivateNegative,
}

impl Endpoint {
    fn socket(&self) -> Result<SocketAddr, String> {
        let ip = match self.address {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(self.address),
            ip => ip,
        };
        if self.port == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v) if v.octets()[0] >= 240)
        {
            return Err("invalid resolver endpoint".into());
        }
        Ok(SocketAddr::new(ip, self.port))
    }
}

impl Group {
    pub fn compile(&self) -> Result<Arc<Forwarder>, String> {
        if self.primary.is_empty()
            || self.primary.len() > 8
            || self.fallback.len() > 8
            || !(100..=10000).contains(&self.timeout_ms)
            || !(self.timeout_ms..=30000).contains(&self.deadline_ms)
        {
            return Err("invalid resolver group limits".into());
        }
        let primary = self
            .primary
            .iter()
            .map(Endpoint::socket)
            .collect::<Result<Vec<_>, _>>()?;
        let fallback = self
            .fallback
            .iter()
            .map(Endpoint::socket)
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique = std::collections::HashSet::new();
        if primary.iter().chain(&fallback).any(|a| !unique.insert(*a)) {
            return Err("duplicate resolver endpoint".into());
        }
        Ok(Arc::new(Forwarder::configured(
            primary,
            fallback,
            self.strategy,
            Duration::from_millis(self.timeout_ms),
            Duration::from_millis(self.deadline_ms),
        )))
    }
}

impl Routing {
    pub fn compile(default: &Group, routes: Vec<Route>) -> Result<Self, String> {
        if routes.len() > 256 {
            return Err("too many conditional routes".into());
        }
        let mut table = HashMap::new();
        let mut ids = std::collections::HashSet::new();
        for route in routes {
            if route.id.is_empty()
                || route.id.len() > 64
                || !route
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                || !ids.insert(route.id)
                || route.domains.is_empty()
                || route.domains.len() > 32
            {
                return Err("invalid route identity or suffix count".into());
            }
            let group = Group {
                primary: route.primary,
                fallback: route.fallback,
                strategy: route.strategy,
                timeout_ms: route.timeout_ms,
                deadline_ms: route.deadline_ms,
            }
            .compile()?;
            for domain in route.domains {
                let suffix = normalize_suffix(&domain)?;
                if table.insert(suffix, group.clone()).is_some() {
                    return Err("duplicate conditional suffix".into());
                }
            }
        }
        Ok(Self {
            default: default.compile()?,
            routes: table,
            private: None,
        })
    }

    #[cfg(test)]
    pub fn from_forwarder(default: Arc<Forwarder>) -> Self {
        Self {
            default,
            routes: HashMap::new(),
            private: None,
        }
    }

    pub fn decide(&self, domain: &str, qtype: u16) -> Decision {
        if let Some(group) = self.conditional(domain) {
            return Decision::Forward(group);
        }
        if qtype == 12 && private_reverse(domain) {
            return self
                .private
                .clone()
                .map(Decision::Forward)
                .unwrap_or(Decision::PrivateNegative);
        }
        Decision::Forward(self.default.clone())
    }

    pub fn conditional(&self, domain: &str) -> Option<Arc<Forwarder>> {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut suffix = normalized.as_str();
        loop {
            if let Some(group) = self.routes.get(suffix) {
                return Some(group.clone());
            }
            match suffix.split_once('.') {
                Some((_, tail)) => suffix = tail,
                None => return None,
            }
        }
    }
}

pub fn private_reverse(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = d.strip_suffix(".in-addr.arpa") {
        let labels: Vec<u8> = match prefix.split('.').rev().map(str::parse).collect() {
            Ok(v) => v,
            Err(_) => return false,
        };
        return matches!(
            labels.as_slice(),
            [10, ..] | [127, ..] | [192, 168, ..] | [169, 254, ..] | [172, 16..=31, ..]
        );
    }
    if let Some(prefix) = d.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = prefix.split('.').rev().collect();
        if nibbles.is_empty()
            || nibbles.len() > 32
            || !nibbles
                .iter()
                .all(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_hexdigit())
        {
            return false;
        }
        let first = u8::from_str_radix(nibbles[0], 16).unwrap_or(0);
        let second = nibbles
            .get(1)
            .and_then(|n| u8::from_str_radix(n, 16).ok())
            .unwrap_or(0);
        return matches!(first, 0xf)
            && (second >= 0xc
                || (second >= 8
                    && nibbles
                        .get(2)
                        .is_some_and(|n| matches!(*n, "8" | "9" | "a" | "b"))))
            || (nibbles.len() == 32
                && nibbles[..31].iter().all(|n| *n == "0")
                && nibbles[31] == "1");
    }
    false
}

fn normalize_suffix(domain: &str) -> Result<String, String> {
    let suffix = domain
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    if suffix.is_empty()
        || suffix.len() > 253
        || suffix.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("invalid DNS suffix".into());
    }
    Ok(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group(ip: &str) -> Group {
        Group {
            primary: vec![Endpoint {
                address: ip.parse().unwrap(),
                port: 53,
            }],
            fallback: vec![],
            strategy: Strategy::Sequential,
            timeout_ms: 2000,
            deadline_ms: 6000,
        }
    }
    fn route(id: &str, suffix: &str) -> Route {
        let g = group("192.0.2.1");
        Route {
            id: id.into(),
            domains: vec![suffix.into()],
            primary: g.primary,
            fallback: g.fallback,
            strategy: g.strategy,
            timeout_ms: g.timeout_ms,
            deadline_ms: g.deadline_ms,
        }
    }
    #[test]
    fn longest_suffix_and_label_boundaries() {
        let r = Routing::compile(
            &group("10.43.230.142"),
            vec![route("lan", "Internal."), route("corp", "corp.internal")],
        )
        .unwrap();
        let base = r.conditional("internal").unwrap();
        assert!(Arc::ptr_eq(
            &base,
            &r.conditional("HOST.Internal.").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &base,
            &r.conditional("host.corp.internal").unwrap()
        ));
        assert!(r.conditional("notinternal").is_none());
        assert!(r.conditional("internal.example").is_none());
        assert_eq!(r.default.upstream_count(), 1);
    }
    #[test]
    fn private_reverse_ranges_are_enumerated() {
        for d in [
            "1.0.0.10.in-addr.arpa",
            "1.0.16.172.in-addr.arpa",
            "1.1.168.192.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "1.1.254.169.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
        ] {
            assert!(private_reverse(d), "{d}");
        }
        for d in [
            "1.0.32.172.in-addr.arpa",
            "8.8.8.8.in-addr.arpa",
            "bad.10.in-addr.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ] {
            assert!(!private_reverse(d), "{d}");
        }
    }

    #[test]
    fn invalid_and_duplicate_routes_rejected() {
        for bad in [
            "",
            "a..b",
            "*.internal",
            "[/internal/]",
            "-internal",
            "internal..",
        ] {
            assert!(Routing::compile(&group("192.0.2.1"), vec![route("lan", bad)]).is_err());
        }
        assert!(Routing::compile(
            &group("192.0.2.1"),
            vec![route("a", "internal"), route("b", "Internal.")]
        )
        .is_err());
        assert!(Routing::compile(
            &group("192.0.2.1"),
            vec![route("a", "one"), route("a", "two")]
        )
        .is_err());
    }
    #[test]
    fn invalid_endpoints_and_limits_rejected() {
        for ip in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            "::ffff:224.0.0.1",
        ] {
            assert!(group(ip).compile().is_err());
        }
        let mut g = group("::1");
        g.deadline_ms = 100;
        assert!(g.compile().is_err());
        g.deadline_ms = 3000;
        g.primary[0].port = 0;
        assert!(g.compile().is_err());
    }
    #[test]
    fn literal_addresses_and_known_fields_required() {
        assert!(
            serde_json::from_str::<Endpoint>(r#"{"address":"resolver.example","port":53}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Endpoint>(r#"{"address":"192.0.2.1","port":53,"url":"x"}"#)
                .is_err()
        );
    }
}
