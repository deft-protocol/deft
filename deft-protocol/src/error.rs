use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeftErrorCode {
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    UpgradeRequired = 426,
    RateLimited = 429,
    InternalServerError = 500,
}

impl DeftErrorCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn message(&self) -> &'static str {
        match self {
            DeftErrorCode::BadRequest => "Bad Request",
            DeftErrorCode::Unauthorized => "Unauthorized - Invalid partner",
            DeftErrorCode::Forbidden => "Forbidden - Partner not allowed",
            DeftErrorCode::NotFound => "Not Found",
            DeftErrorCode::UpgradeRequired => "Upgrade Required - Version not supported",
            DeftErrorCode::RateLimited => "Too Many Requests - Rate limit exceeded",
            DeftErrorCode::InternalServerError => "Internal Server Error",
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            400 => Some(DeftErrorCode::BadRequest),
            401 => Some(DeftErrorCode::Unauthorized),
            403 => Some(DeftErrorCode::Forbidden),
            404 => Some(DeftErrorCode::NotFound),
            426 => Some(DeftErrorCode::UpgradeRequired),
            429 => Some(DeftErrorCode::RateLimited),
            500 => Some(DeftErrorCode::InternalServerError),
            _ => None,
        }
    }
}

impl fmt::Display for DeftErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code(), self.message())
    }
}

#[derive(Debug, Error)]
pub enum DeftError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unknown command: {0}")]
    UnknownCommand(String),

    #[error("Unknown capability: {0}")]
    UnknownCapability(String),

    #[error("Invalid chunk range: {0}")]
    InvalidChunkRange(String),

    #[error("Protocol error: {0}")]
    ProtocolError(DeftErrorCode),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid hash: {0}")]
    InvalidHash(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_values() {
        assert_eq!(DeftErrorCode::BadRequest.code(), 400);
        assert_eq!(DeftErrorCode::Unauthorized.code(), 401);
        assert_eq!(DeftErrorCode::Forbidden.code(), 403);
        assert_eq!(DeftErrorCode::NotFound.code(), 404);
        assert_eq!(DeftErrorCode::UpgradeRequired.code(), 426);
        assert_eq!(DeftErrorCode::RateLimited.code(), 429);
        assert_eq!(DeftErrorCode::InternalServerError.code(), 500);
    }

    #[test]
    fn test_error_code_messages() {
        assert_eq!(DeftErrorCode::BadRequest.message(), "Bad Request");
        assert_eq!(
            DeftErrorCode::Unauthorized.message(),
            "Unauthorized - Invalid partner"
        );
        assert_eq!(
            DeftErrorCode::Forbidden.message(),
            "Forbidden - Partner not allowed"
        );
        assert_eq!(DeftErrorCode::NotFound.message(), "Not Found");
        assert_eq!(
            DeftErrorCode::UpgradeRequired.message(),
            "Upgrade Required - Version not supported"
        );
        assert_eq!(
            DeftErrorCode::RateLimited.message(),
            "Too Many Requests - Rate limit exceeded"
        );
        assert_eq!(
            DeftErrorCode::InternalServerError.message(),
            "Internal Server Error"
        );
    }

    #[test]
    fn test_error_code_from_code() {
        assert_eq!(
            DeftErrorCode::from_code(400),
            Some(DeftErrorCode::BadRequest)
        );
        assert_eq!(
            DeftErrorCode::from_code(401),
            Some(DeftErrorCode::Unauthorized)
        );
        assert_eq!(
            DeftErrorCode::from_code(403),
            Some(DeftErrorCode::Forbidden)
        );
        assert_eq!(DeftErrorCode::from_code(404), Some(DeftErrorCode::NotFound));
        assert_eq!(
            DeftErrorCode::from_code(426),
            Some(DeftErrorCode::UpgradeRequired)
        );
        assert_eq!(
            DeftErrorCode::from_code(429),
            Some(DeftErrorCode::RateLimited)
        );
        assert_eq!(
            DeftErrorCode::from_code(500),
            Some(DeftErrorCode::InternalServerError)
        );
        assert_eq!(DeftErrorCode::from_code(999), None);
    }

    #[test]
    fn test_error_code_display() {
        let display = format!("{}", DeftErrorCode::NotFound);
        assert!(display.contains("404"));
        assert!(display.contains("Not Found"));
    }

    #[test]
    fn test_deft_error_parse_error() {
        let err = DeftError::ParseError("invalid syntax".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Parse error"));
        assert!(msg.contains("invalid syntax"));
    }

    #[test]
    fn test_deft_error_unknown_command() {
        let err = DeftError::UnknownCommand("FOOBAR".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Unknown command"));
        assert!(msg.contains("FOOBAR"));
    }

    #[test]
    fn test_deft_error_unknown_capability() {
        let err = DeftError::UnknownCapability("TELEPORT".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Unknown capability"));
    }

    #[test]
    fn test_deft_error_invalid_chunk_range() {
        let err = DeftError::InvalidChunkRange("5-3".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid chunk range"));
    }

    #[test]
    fn test_deft_error_protocol_error() {
        let err = DeftError::ProtocolError(DeftErrorCode::Forbidden);
        let msg = format!("{}", err);
        assert!(msg.contains("Protocol error"));
    }

    #[test]
    fn test_deft_error_missing_field() {
        let err = DeftError::MissingField("transfer_id".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Missing required field"));
        assert!(msg.contains("transfer_id"));
    }

    #[test]
    fn test_deft_error_invalid_hash() {
        let err = DeftError::InvalidHash("not-a-hash".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid hash"));
    }

    #[test]
    fn test_error_code_serialization() {
        let code = DeftErrorCode::RateLimited;
        let json = serde_json::to_string(&code).unwrap();
        let parsed: DeftErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, parsed);
    }
}
