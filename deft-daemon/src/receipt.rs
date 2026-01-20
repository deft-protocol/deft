//! Receipt storage and retrieval.
//! 
//! Some methods reserved for receipt querying.
#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use deft_protocol::TransferReceipt;
use tracing::{error, info};

pub struct ReceiptStore {
    base_path: PathBuf,
}

impl ReceiptStore {
    pub fn new<P: AsRef<Path>>(base_path: P) -> std::io::Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&base_path)?;
        Ok(Self { base_path })
    }

    pub fn store(&self, receipt: &TransferReceipt) -> std::io::Result<PathBuf> {
        let date_path = self.date_path();
        fs::create_dir_all(&date_path)?;

        let filename = format!("transfer_{}.json", receipt.transfer_id);
        let filepath = date_path.join(&filename);

        let json = serde_json::to_string_pretty(receipt)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = File::create(&filepath)?;
        file.write_all(json.as_bytes())?;

        info!(
            "Stored receipt for transfer {} at {:?}",
            receipt.transfer_id, filepath
        );

        // Also append to the append-only log
        self.append_to_log(receipt)?;

        Ok(filepath)
    }

    fn append_to_log(&self, receipt: &TransferReceipt) -> std::io::Result<()> {
        let log_path = self.base_path.join("receipts.log");

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let json = serde_json::to_string(receipt)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(file, "{}", json)?;

        Ok(())
    }

    fn date_path(&self) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let secs_per_day = 86400;
        let days_since_epoch = now / secs_per_day;

        // Simple date calculation (approximate, good enough for directory naming)
        let year = 1970 + (days_since_epoch / 365);
        let day_of_year = days_since_epoch % 365;
        let month = (day_of_year / 30) + 1;
        let day = (day_of_year % 30) + 1;

        self.base_path.join(format!(
            "{:04}/{:02}/{:02}",
            year,
            month.min(12),
            day.min(31)
        ))
    }

    pub fn load(&self, transfer_id: &str) -> std::io::Result<TransferReceipt> {
        // Search in recent date directories
        let entries = fs::read_dir(&self.base_path)?;

        for entry in entries.flatten() {
            if entry.file_type()?.is_dir() {
                if let Some(receipt) = self.search_in_dir(&entry.path(), transfer_id)? {
                    return Ok(receipt);
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Receipt not found: {}", transfer_id),
        ))
    }

    fn search_in_dir(
        &self,
        dir: &Path,
        transfer_id: &str,
    ) -> std::io::Result<Option<TransferReceipt>> {
        let filename = format!("transfer_{}.json", transfer_id);
        let filepath = dir.join(&filename);

        if filepath.exists() {
            let content = fs::read_to_string(&filepath)?;
            let receipt: TransferReceipt = serde_json::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            return Ok(Some(receipt));
        }

        // Recursively search subdirectories
        for entry in fs::read_dir(dir)?.flatten() {
            if entry.file_type()?.is_dir() {
                if let Some(receipt) = self.search_in_dir(&entry.path(), transfer_id)? {
                    return Ok(Some(receipt));
                }
            }
        }

        Ok(None)
    }

    pub fn list_recent(&self, limit: usize) -> std::io::Result<Vec<TransferReceipt>> {
        let log_path = self.base_path.join("receipts.log");

        if !log_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&log_path)?;
        let lines: Vec<&str> = content.lines().collect();

        let mut receipts = Vec::new();
        for line in lines.iter().rev().take(limit) {
            match serde_json::from_str(line) {
                Ok(receipt) => receipts.push(receipt),
                Err(e) => error!("Failed to parse receipt line: {}", e),
            }
        }

        Ok(receipts)
    }
}

impl Default for ReceiptStore {
    fn default() -> Self {
        Self::new("/var/deft/receipts").unwrap_or_else(|_| {
            Self::new("/tmp/deft/receipts").expect("Failed to create receipt store")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_store_and_load() {
        let temp_dir = env::temp_dir().join("deft_test_receipts");
        let _ = fs::remove_dir_all(&temp_dir);

        let store = ReceiptStore::new(&temp_dir).unwrap();

        let receipt = TransferReceipt {
            transfer_id: "test-123".into(),
            virtual_file: "test-file".into(),
            sender_partner: "sender".into(),
            receiver_partner: "receiver".into(),
            timestamp_start: "2026-01-19T14:30:00Z".into(),
            timestamp_complete: "2026-01-19T14:35:00Z".into(),
            chunks_total: 10,
            total_bytes: 1024000,
            file_hash: "sha256:abc123".into(),
            signature: None,
        };

        store.store(&receipt).unwrap();

        let loaded = store.load("test-123").unwrap();
        assert_eq!(loaded.transfer_id, receipt.transfer_id);
        assert_eq!(loaded.virtual_file, receipt.virtual_file);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
