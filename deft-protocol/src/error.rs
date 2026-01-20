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
