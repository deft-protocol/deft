//! Platform-specific utilities.
//! 
//! Some functions are reserved for future CLI/config tooling.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Platform-specific path handling
pub fn normalize_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        // Convert forward slashes to backslashes on Windows
        let path_str = path.to_string_lossy();
        PathBuf::from(path_str.replace('/', "\\"))
    }

    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// Get platform-specific default config path
pub fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        // Windows: %PROGRAMDATA%\deft\config.toml or C:\deft\config.toml
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            PathBuf::from(program_data).join("deft").join("config.toml")
        } else {
            PathBuf::from("C:\\deft\\config.toml")
        }
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/deft/config.toml")
    }
}

/// Get platform-specific default temp directory
pub fn default_temp_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(temp) = std::env::var("TEMP") {
            PathBuf::from(temp).join("deft")
        } else {
            PathBuf::from("C:\\deft\\tmp")
        }
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/var/deft/tmp")
    }
}

/// Get platform-specific default data directory
pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            PathBuf::from(program_data).join("deft").join("data")
        } else {
            PathBuf::from("C:\\deft\\data")
        }
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/var/deft/data")
    }
}

/// Get platform-specific certificate directory
pub fn default_certs_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            PathBuf::from(program_data).join("deft").join("certs")
        } else {
            PathBuf::from("C:\\deft\\certs")
        }
    }

    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/deft/certs")
    }
}

/// Platform-specific line ending
pub fn line_ending() -> &'static str {
    #[cfg(windows)]
    {
        "\r\n"
    }

    #[cfg(not(windows))]
    {
        "\n"
    }
}

/// Check if running as administrator/root
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        // On Windows, check if running as administrator
        std::env::var("USERNAME")
            .map(|u| u.to_lowercase() == "administrator")
            .unwrap_or(false)
    }

    #[cfg(unix)]
    {
        // On Unix, check if running as root (uid 0)
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }

    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// Create directory with appropriate permissions
pub fn create_secure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

/// Platform information for diagnostics
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub family: &'static str,
}

impl PlatformInfo {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            family: std::env::consts::FAMILY,
        }
    }
}

impl std::fmt::Display for PlatformInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{} ({})", self.os, self.arch, self.family)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info() {
        let info = PlatformInfo::current();
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
    }

    #[test]
    fn test_default_paths() {
        let config = default_config_path();
        let temp = default_temp_dir();
        let data = default_data_dir();

        assert!(config.to_string_lossy().contains("deft"));
        assert!(temp.to_string_lossy().contains("deft"));
        assert!(data.to_string_lossy().contains("deft"));
    }

    #[test]
    fn test_normalize_path() {
        let path = Path::new("/some/path/file.txt");
        let normalized = normalize_path(path);

        #[cfg(windows)]
        assert!(normalized.to_string_lossy().contains("\\"));

        #[cfg(not(windows))]
        assert_eq!(normalized, path);
    }
}
