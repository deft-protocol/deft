use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiftErrorCode {
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    UpgradeRequired = 426,
    RateLimited = 429,
    InternalServerError = 500,
}

impl RiftErrorCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn message(&self) -> &'static str {
        match self {
            RiftErrorCode::BadRequest => "Bad Request",
            RiftErrorCode::Unauthorized => "Unauthorized - Invalid partner",
            RiftErrorCode::Forbidden => "Forbidden - Partner not allowed",
            RiftErrorCode::NotFound => "Not Found",
            RiftErrorCode::UpgradeRequired => "Upgrade Required - Version not supported",
            RiftErrorCode::RateLimited => "Too Many Requests - Rate limit exceeded",
            RiftErrorCode::InternalServerError => "Internal Server Error",
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            400 => Some(RiftErrorCode::BadRequest),
            401 => Some(RiftErrorCode::Unauthorized),
            403 => Some(RiftErrorCode::Forbidden),
            404 => Some(RiftErrorCode::NotFound),
            426 => Some(RiftErrorCode::UpgradeRequired),
            429 => Some(RiftErrorCode::RateLimited),
            500 => Some(RiftErrorCode::InternalServerError),
            _ => None,
        }
    }
}

impl fmt::Display for RiftErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code(), self.message())
    }
}

#[derive(Debug, Error)]
pub enum RiftError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unknown command: {0}")]
    UnknownCommand(String),

    #[error("Unknown capability: {0}")]
    UnknownCapability(String),

    #[error("Invalid chunk range: {0}")]
    InvalidChunkRange(String),

    #[error("Protocol error: {0}")]
    ProtocolError(RiftErrorCode),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid hash: {0}")]
    InvalidHash(String),
}
