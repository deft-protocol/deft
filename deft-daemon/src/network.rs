//! Network interface detection for parallel multi-path transfers.
//!
//! Detects available network interfaces and their IP addresses to enable
//! parallel transfers over multiple network paths.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Information about a network interface
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,
    /// Whether this interface is up and running
    pub is_up: bool,
    /// Whether this is a loopback interface
    pub is_loopback: bool,
}

impl NetworkInterface {
    /// Get the first IPv4 address, if any
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|addr| match addr {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
    }

    /// Get the first IPv6 address, if any
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.addresses.iter().find_map(|addr| match addr {
            IpAddr::V6(v6) => Some(*v6),
            _ => None,
        })
    }
}

/// Detect all available network interfaces
#[cfg(unix)]
pub fn detect_interfaces() -> Vec<NetworkInterface> {
    use nix::ifaddrs::getifaddrs;
    use std::collections::HashMap;

    let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

    if let Ok(addrs) = getifaddrs() {
        for ifaddr in addrs {
            let name = ifaddr.interface_name.clone();
            let entry = interfaces
                .entry(name.clone())
                .or_insert_with(|| NetworkInterface {
                    name: name.clone(),
                    addresses: Vec::new(),
                    is_up: ifaddr.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP),
                    is_loopback: ifaddr
                        .flags
                        .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK),
                });

            // Extract IP address
            if let Some(addr) = ifaddr.address {
                if let Some(sockaddr) = addr.as_sockaddr_in() {
                    entry.addresses.push(IpAddr::V4(sockaddr.ip()));
                } else if let Some(sockaddr) = addr.as_sockaddr_in6() {
                    entry.addresses.push(IpAddr::V6(sockaddr.ip()));
                }
            }
        }
    }

    interfaces.into_values().collect()
}

/// Detect all available network interfaces (Windows)
#[cfg(windows)]
pub fn detect_interfaces() -> Vec<NetworkInterface> {
    // Simplified Windows implementation - uses standard library
    // For full implementation, use windows crate with GetAdaptersAddresses
    use std::net::UdpSocket;

    let mut interfaces = Vec::new();

    // Detect local IP by connecting to external address (doesn't actually send data)
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                interfaces.push(NetworkInterface {
                    name: "default".to_string(),
                    addresses: vec![local_addr.ip()],
                    is_up: true,
                    is_loopback: false,
                });
            }
        }
    }

    // Always add loopback
    interfaces.push(NetworkInterface {
        name: "loopback".to_string(),
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        is_up: true,
        is_loopback: true,
    });

    interfaces
}

/// Get usable interfaces for parallel transfers (excludes loopback, must be up)
pub fn get_transfer_interfaces() -> Vec<NetworkInterface> {
    detect_interfaces()
        .into_iter()
        .filter(|iface| iface.is_up && !iface.is_loopback && !iface.addresses.is_empty())
        .collect()
}

/// Suggest optimal parallel stream count based on available interfaces
pub fn suggest_parallel_streams() -> usize {
    let interfaces = get_transfer_interfaces();
    let count = interfaces.len();

    if count == 0 {
        1 // Fallback to sequential
    } else if count == 1 {
        // Single interface: use 2-4 streams for better throughput
        4
    } else {
        // Multiple interfaces: one stream per interface, max 8
        count.min(8)
    }
}

/// Get binding addresses for parallel streams
#[allow(dead_code)]
pub fn get_binding_addresses(count: usize) -> Vec<Option<IpAddr>> {
    let interfaces = get_transfer_interfaces();

    if interfaces.is_empty() {
        // No specific binding, let OS choose
        return vec![None; count];
    }

    let mut addresses: Vec<Option<IpAddr>> = Vec::with_capacity(count);

    // Distribute across interfaces
    for i in 0..count {
        let iface = &interfaces[i % interfaces.len()];
        addresses.push(iface.ipv4().map(IpAddr::V4));
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_interfaces() {
        let interfaces = detect_interfaces();
        // Should at least have loopback
        assert!(
            !interfaces.is_empty(),
            "Should detect at least one interface"
        );

        // Print for debugging
        for iface in &interfaces {
            println!(
                "Interface: {} (up={}, loopback={}) - {:?}",
                iface.name, iface.is_up, iface.is_loopback, iface.addresses
            );
        }
    }

    #[test]
    fn test_get_transfer_interfaces() {
        let interfaces = get_transfer_interfaces();
        // All returned interfaces should be up and not loopback
        for iface in &interfaces {
            assert!(iface.is_up, "Interface should be up");
            assert!(!iface.is_loopback, "Interface should not be loopback");
            assert!(
                !iface.addresses.is_empty(),
                "Interface should have addresses"
            );
        }
    }

    #[test]
    fn test_suggest_parallel_streams() {
        let count = suggest_parallel_streams();
        assert!(count >= 1, "Should suggest at least 1 stream");
        assert!(count <= 8, "Should not suggest more than 8 streams");
    }

    #[test]
    fn test_get_binding_addresses() {
        let addresses = get_binding_addresses(4);
        assert_eq!(addresses.len(), 4);
    }
}
