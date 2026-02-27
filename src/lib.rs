//! Shared libp2p utilities for the Fortytwo Network.
//!
//! Provides address filtering helpers that determine whether a multiaddr
//! is globally reachable. Used by protocol nodes, relays, and bootstrap
//! nodes to prevent non-routable addresses (Docker bridge, RFC 1918,
//! loopback, link-local, etc.) from entering the Kademlia DHT.

pub use libp2p::multiaddr::{Multiaddr, Protocol};

use std::net::{Ipv4Addr, Ipv6Addr};

/// Returns `true` if the given IPv4 address is globally reachable.
///
/// Rejects:
/// - RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
/// - Loopback (127/8)
/// - Link-local (169.254/16)
/// - RFC 5737 documentation/test networks (192.0.2/24, 198.51.100/24, 203.0.113/24)
fn is_global_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        // RFC 5737 TEST-NET-1
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        // RFC 5737 TEST-NET-2
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        // RFC 5737 TEST-NET-3
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

/// Returns `true` if the given IPv6 address is globally reachable.
///
/// Rejects:
/// - Loopback (::1)
/// - Unspecified (::)
/// - Unique-local (fc00::/7)
/// - Link-local (fe80::/10)
fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_unique_local()
        // Link-local (fe80::/10)
        && (segments[0] & 0xffc0 != 0xfe80)
}

/// Returns `true` if a single multiaddr is globally reachable.
///
/// - Addrs with IP components: accepted only if **all** IP components are global.
/// - Addrs without IP components (DNS, `/p2p-circuit`, etc.): always accepted.
///
/// # Examples
///
/// ```
/// use fortytwo_libp2p_utils::{is_global_ip_addr, Multiaddr};
///
/// let public: Multiaddr = "/ip4/1.2.3.4/tcp/4242".parse().unwrap();
/// assert!(is_global_ip_addr(&public));
///
/// let private: Multiaddr = "/ip4/192.168.1.1/tcp/4242".parse().unwrap();
/// assert!(!is_global_ip_addr(&private));
///
/// let circuit: Multiaddr = "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit".parse().unwrap();
/// assert!(is_global_ip_addr(&circuit));
/// ```
pub fn is_global_ip_addr(addr: &Multiaddr) -> bool {
    let has_ip = addr.iter().any(|proto| {
        matches!(proto, Protocol::Ip4(_) | Protocol::Ip6(_))
    });

    if !has_ip {
        // No IP components — DNS, p2p-circuit, etc. Pass through.
        return true;
    }

    // Has IP components — all must be globally reachable.
    addr.iter().all(|proto| match proto {
        Protocol::Ip4(ip) => is_global_ipv4(&ip),
        Protocol::Ip6(ip) => is_global_ipv6(&ip),
        _ => true,
    })
}

/// Filter an iterator of multiaddrs, keeping only globally reachable ones.
///
/// - Addrs with IP components: kept only if **all** IP components are global.
/// - Addrs without IP components (DNS, `/p2p-circuit`, etc.): always kept.
///
/// # Examples
///
/// ```
/// use fortytwo_libp2p_utils::{filter_global_ip_addrs, Multiaddr};
///
/// let addrs: Vec<Multiaddr> = vec![
///     "/ip4/1.2.3.4/tcp/4242".parse().unwrap(),
///     "/ip4/172.18.0.2/tcp/4242".parse().unwrap(),
///     "/ip4/127.0.0.1/tcp/4242".parse().unwrap(),
/// ];
/// let global = filter_global_ip_addrs(addrs);
/// assert_eq!(global.len(), 1);
/// ```
pub fn filter_global_ip_addrs<I>(addrs: I) -> Vec<Multiaddr>
where
    I: IntoIterator<Item = Multiaddr>,
{
    addrs
        .into_iter()
        .filter(|ma| is_global_ip_addr(ma))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_docker_bridge() {
        let addr: Multiaddr = "/ip4/172.18.0.2/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_rfc1918_10() {
        let addr: Multiaddr = "/ip4/10.0.0.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_rfc1918_192_168() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_loopback() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_test_net_1() {
        let addr: Multiaddr = "/ip4/192.0.2.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_test_net_2() {
        let addr: Multiaddr = "/ip4/198.51.100.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_test_net_3() {
        let addr: Multiaddr = "/ip4/203.0.113.5/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_link_local() {
        let addr: Multiaddr = "/ip4/169.254.1.1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn accepts_public_ipv4() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4242".parse().unwrap();
        assert!(is_global_ip_addr(&addr));
    }

    #[test]
    fn accepts_public_ipv4_quic() {
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4242/quic-v1".parse().unwrap();
        assert!(is_global_ip_addr(&addr));
    }

    #[test]
    fn accepts_p2p_circuit() {
        let addr: Multiaddr = "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit".parse().unwrap();
        assert!(is_global_ip_addr(&addr));
    }

    #[test]
    fn accepts_dns_addr() {
        let addr: Multiaddr = "/dns4/bootstrap.example.com/tcp/4242".parse().unwrap();
        assert!(is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        let addr: Multiaddr = "/ip6/::1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_ipv6_link_local() {
        let addr: Multiaddr = "/ip6/fe80::1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_ipv6_unique_local() {
        let addr: Multiaddr = "/ip6/fd00::1/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn rejects_ipv6_unspecified() {
        let addr: Multiaddr = "/ip6/::/tcp/4242".parse().unwrap();
        assert!(!is_global_ip_addr(&addr));
    }

    #[test]
    fn accepts_public_ipv6() {
        let addr: Multiaddr = "/ip6/2001:db8::1/tcp/4242".parse().unwrap();
        // 2001:db8::/32 is documentation range but not filtered here
        // (only the IPv4 test nets are filtered; IPv6 documentation range
        // is less commonly encountered in practice)
        assert!(is_global_ip_addr(&addr));
    }

    #[test]
    fn filter_keeps_only_global() {
        let addrs: Vec<Multiaddr> = vec![
            "/ip4/1.2.3.4/tcp/4242".parse().unwrap(),
            "/ip4/172.18.0.2/tcp/4242".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/4242".parse().unwrap(),
            "/ip4/10.0.0.1/tcp/4242".parse().unwrap(),
            "/ip4/5.6.7.8/udp/4242/quic-v1".parse().unwrap(),
        ];
        let global = filter_global_ip_addrs(addrs);
        assert_eq!(global.len(), 2);
        assert_eq!(
            global[0],
            "/ip4/1.2.3.4/tcp/4242".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(
            global[1],
            "/ip4/5.6.7.8/udp/4242/quic-v1"
                .parse::<Multiaddr>()
                .unwrap()
        );
    }
}
