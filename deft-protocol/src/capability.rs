use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Chunked,
    Parallel,
    Resume,
    Compress,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Chunked => write!(f, "CHUNKED"),
            Capability::Parallel => write!(f, "PARALLEL"),
            Capability::Resume => write!(f, "RESUME"),
            Capability::Compress => write!(f, "COMPRESS"),
        }
    }
}

impl FromStr for Capability {
    type Err = crate::RiftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CHUNKED" => Ok(Capability::Chunked),
            "PARALLEL" => Ok(Capability::Parallel),
            "RESUME" => Ok(Capability::Resume),
            "COMPRESS" | "GZIP" => Ok(Capability::Compress),
            _ => Err(crate::RiftError::UnknownCapability(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub caps: Vec<Capability>,
    pub window_size: Option<u32>,
}

pub const DEFAULT_WINDOW_SIZE: u32 = 64;

impl Capabilities {
    pub fn new() -> Self {
        Self {
            caps: Vec::new(),
            window_size: None,
        }
    }

    pub fn all() -> Self {
        Self {
            caps: vec![
                Capability::Chunked,
                Capability::Parallel,
                Capability::Resume,
                Capability::Compress,
            ],
            window_size: Some(DEFAULT_WINDOW_SIZE),
        }
    }

    pub fn with_window_size(mut self, size: u32) -> Self {
        self.window_size = Some(size);
        self
    }

    pub fn has(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    #[must_use]
    pub fn with(mut self, cap: Capability) -> Self {
        if !self.has(cap) {
            self.caps.push(cap);
        }
        self
    }

    pub fn effective_window_size(&self, other: &Capabilities) -> u32 {
        let self_size = self.window_size.unwrap_or(DEFAULT_WINDOW_SIZE);
        let other_size = other.window_size.unwrap_or(DEFAULT_WINDOW_SIZE);
        self_size.min(other_size)
    }

    pub fn intersect(&self, other: &Capabilities) -> Capabilities {
        let caps: Vec<Capability> = self
            .caps
            .iter()
            .filter(|c| other.has(**c))
            .copied()
            .collect();
        let window_size = Some(self.effective_window_size(other));
        Capabilities { caps, window_size }
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.caps.iter().map(|c| c.to_string()).collect();
        let caps_str = s.join(",");
        if let Some(ws) = self.window_size {
            if caps_str.is_empty() {
                write!(f, "WINDOW_SIZE:{}", ws)
            } else {
                write!(f, "{} WINDOW_SIZE:{}", caps_str, ws)
            }
        } else {
            write!(f, "{}", caps_str)
        }
    }
}

impl FromStr for Capabilities {
    type Err = crate::RiftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Capabilities::new());
        }

        let mut caps = Vec::new();
        let mut window_size = None;

        for part in s.split([',', ' ']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(ws) = part.strip_prefix("WINDOW_SIZE:") {
                window_size = Some(ws.parse().map_err(|_| {
                    crate::RiftError::ParseError(format!("Invalid window size: {}", ws))
                })?);
            } else {
                caps.push(part.parse()?);
            }
        }

        Ok(Capabilities { caps, window_size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_new() {
        let caps = Capabilities::new();
        assert!(caps.caps.is_empty());
        assert!(caps.window_size.is_none());
    }

    #[test]
    fn test_capabilities_all() {
        let caps = Capabilities::all();
        assert!(caps.has(Capability::Chunked));
        assert!(caps.has(Capability::Parallel));
        assert!(caps.has(Capability::Resume));
        assert_eq!(caps.window_size, Some(DEFAULT_WINDOW_SIZE));
    }

    #[test]
    fn test_capabilities_with_window_size() {
        let caps = Capabilities::new().with_window_size(128);
        assert_eq!(caps.window_size, Some(128));
    }

    #[test]
    fn test_capabilities_intersect() {
        let client = Capabilities::all().with_window_size(128);
        let server = Capabilities::new()
            .with(Capability::Chunked)
            .with(Capability::Resume)
            .with_window_size(64);

        let negotiated = server.intersect(&client);

        assert!(negotiated.has(Capability::Chunked));
        assert!(negotiated.has(Capability::Resume));
        assert!(!negotiated.has(Capability::Parallel));
        // Should use the minimum window size
        assert_eq!(negotiated.window_size, Some(64));
    }

    #[test]
    fn test_capabilities_effective_window_size() {
        let caps1 = Capabilities::new().with_window_size(100);
        let caps2 = Capabilities::new().with_window_size(50);

        assert_eq!(caps1.effective_window_size(&caps2), 50);
        assert_eq!(caps2.effective_window_size(&caps1), 50);
    }

    #[test]
    fn test_capabilities_display() {
        let caps = Capabilities::new()
            .with(Capability::Chunked)
            .with(Capability::Parallel)
            .with_window_size(64);

        let s = caps.to_string();
        assert!(s.contains("CHUNKED"));
        assert!(s.contains("PARALLEL"));
        assert!(s.contains("WINDOW_SIZE:64"));
    }

    #[test]
    fn test_capabilities_from_str() {
        let caps: Capabilities = "CHUNKED,PARALLEL WINDOW_SIZE:128".parse().unwrap();
        assert!(caps.has(Capability::Chunked));
        assert!(caps.has(Capability::Parallel));
        assert!(!caps.has(Capability::Resume));
        assert_eq!(caps.window_size, Some(128));
    }

    #[test]
    fn test_capabilities_from_str_no_window() {
        let caps: Capabilities = "CHUNKED,RESUME".parse().unwrap();
        assert!(caps.has(Capability::Chunked));
        assert!(caps.has(Capability::Resume));
        assert!(caps.window_size.is_none());
    }

    #[test]
    fn test_capabilities_from_str_only_window() {
        let caps: Capabilities = "WINDOW_SIZE:32".parse().unwrap();
        assert!(caps.caps.is_empty());
        assert_eq!(caps.window_size, Some(32));
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(Capability::Chunked.to_string(), "CHUNKED");
        assert_eq!(Capability::Parallel.to_string(), "PARALLEL");
        assert_eq!(Capability::Resume.to_string(), "RESUME");
    }

    #[test]
    fn test_capability_from_str() {
        assert_eq!(
            "CHUNKED".parse::<Capability>().unwrap(),
            Capability::Chunked
        );
        assert_eq!(
            "PARALLEL".parse::<Capability>().unwrap(),
            Capability::Parallel
        );
        assert_eq!("RESUME".parse::<Capability>().unwrap(), Capability::Resume);
    }
}
