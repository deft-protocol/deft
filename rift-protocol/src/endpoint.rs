use std::fmt;
use serde::{Deserialize, Serialize};

/// Represents a network endpoint for RIFT connections
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub priority: u8,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl std::str::FromStr for Endpoint {
    type Err = crate::RiftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(crate::RiftError::ParseError(
                format!("Invalid endpoint format: {}", s)
            ));
        }
        
        let host = parts[0].to_string();
        let port: u16 = parts[1].parse()
            .map_err(|_| crate::RiftError::ParseError(
                format!("Invalid port: {}", parts[1])
            ))?;
        
        Ok(Endpoint::new(host, port))
    }
}

/// List of endpoints for parallel transfer
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointList {
    endpoints: Vec<Endpoint>,
}

impl EndpointList {
    pub fn new() -> Self {
        Self { endpoints: Vec::new() }
    }

    pub fn add(&mut self, endpoint: Endpoint) {
        self.endpoints.push(endpoint);
    }

    pub fn from_vec(endpoints: Vec<Endpoint>) -> Self {
        Self { endpoints }
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Endpoint> {
        self.endpoints.iter()
    }

    /// Get endpoints sorted by priority (highest first)
    pub fn by_priority(&self) -> Vec<&Endpoint> {
        let mut sorted: Vec<&Endpoint> = self.endpoints.iter().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        sorted
    }

    /// Get the primary endpoint (highest priority)
    pub fn primary(&self) -> Option<&Endpoint> {
        self.by_priority().first().copied()
    }
}

impl fmt::Display for EndpointList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addrs: Vec<String> = self.endpoints.iter()
            .map(|e| e.to_string())
            .collect();
        write!(f, "{}", addrs.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint() {
        let ep = Endpoint::new("localhost", 7741);
        assert_eq!(ep.host, "localhost");
        assert_eq!(ep.port, 7741);
        assert_eq!(ep.address(), "localhost:7741");
    }

    #[test]
    fn test_endpoint_parse() {
        let ep: Endpoint = "example.com:7741".parse().unwrap();
        assert_eq!(ep.host, "example.com");
        assert_eq!(ep.port, 7741);
    }

    #[test]
    fn test_endpoint_priority() {
        let ep = Endpoint::new("host1", 7741).with_priority(10);
        assert_eq!(ep.priority, 10);
    }

    #[test]
    fn test_endpoint_list() {
        let mut list = EndpointList::new();
        list.add(Endpoint::new("host1", 7741).with_priority(1));
        list.add(Endpoint::new("host2", 7741).with_priority(5));
        list.add(Endpoint::new("host3", 7741).with_priority(3));

        assert_eq!(list.len(), 3);
        
        let by_prio = list.by_priority();
        assert_eq!(by_prio[0].host, "host2");
        assert_eq!(by_prio[1].host, "host3");
        assert_eq!(by_prio[2].host, "host1");

        assert_eq!(list.primary().unwrap().host, "host2");
    }
}
