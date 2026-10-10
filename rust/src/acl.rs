use std::net::IpAddr;

use ipnet::IpNet;

/// Which client addresses may query. Not configured = everyone.
pub struct Acl {
    nets: Vec<IpNet>,
    /// True when any entries were supplied, even if none parsed: a typo'd ACL
    /// fails closed instead of silently becoming an open resolver.
    configured: bool,
}

impl Acl {
    pub fn allow_all() -> Self {
        Self {
            nets: Vec::new(),
            configured: false,
        }
    }

    /// Accepts CIDRs (`10.0.0.0/8`) and bare addresses (`192.168.1.5`).
    pub fn from_cidrs(cidrs: &[String]) -> Self {
        let nets = cidrs
            .iter()
            .filter_map(|c| {
                let c = c.trim();
                c.parse::<IpNet>()
                    .or_else(|_| c.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| tracing::warn!(entry = c, "ignoring invalid ACL entry"))
                    .ok()
            })
            .collect();
        Self {
            nets,
            configured: !cidrs.is_empty(),
        }
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        if !self.configured {
            return true;
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.nets.iter().any(|n| n.contains(&ip))
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(cidrs: &[&str]) -> Acl {
        Acl::from_cidrs(&cidrs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_acl_permits_everyone() {
        assert!(Acl::allow_all().permits(ip("203.0.113.9")));
        assert!(acl(&[]).permits(ip("2001:db8::1")));
    }

    #[test]
    fn permits_only_listed_networks() {
        let a = acl(&["192.168.0.0/16", "10.0.0.0/8", "2001:db8:1::/48"]);
        assert!(a.permits(ip("192.168.1.42")));
        assert!(a.permits(ip("10.1.2.3")));
        assert!(a.permits(ip("2001:db8:1:5::7")));
        assert!(!a.permits(ip("203.0.113.9")));
        assert!(!a.permits(ip("2001:db8:2::1")));
    }

    #[test]
    fn bare_address_means_single_host() {
        let a = acl(&["192.168.1.5", "fd00::1"]);
        assert!(a.permits(ip("192.168.1.5")));
        assert!(!a.permits(ip("192.168.1.6")));
        assert!(a.permits(ip("fd00::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_client_matches_ipv4_rule() {
        // A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d.
        let a = acl(&["192.168.0.0/16"]);
        assert!(a.permits(ip("::ffff:192.168.1.42")));
        assert!(!a.permits(ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn invalid_entries_are_skipped_not_fatal() {
        let a = acl(&["not-a-cidr", "10.0.0.0/8"]);
        assert_eq!(a.len(), 1);
        assert!(a.permits(ip("10.0.0.1")));
        assert!(!a.permits(ip("192.168.1.1")));
    }

    #[test]
    fn only_invalid_entries_fails_closed() {
        // A typo must not silently turn the resolver into an open one.
        let a = acl(&["garbage"]);
        assert!(!a.permits(ip("192.168.1.1")));
    }
}
