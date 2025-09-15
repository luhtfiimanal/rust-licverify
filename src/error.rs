use thiserror::Error;

/// Result type for license operations
pub type LicenseResult<T> = Result<T, LicenseError>;

/// Errors that can occur during license verification
#[derive(Error, Debug)]
pub enum LicenseError {
    #[error("Invalid license signature")]
    InvalidSignature,

    #[error("License has expired on {date}")]
    Expired { date: String },

    #[error("Hardware binding mismatch: {reason}")]
    HardwareBinding { reason: String },

    #[error("Failed to parse license file: {0}")]
    ParseError(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("RSA signature error: {0}")]
    RsaSignature(#[from] rsa::signature::Error),

    #[error("PEM parsing error: {0}")]
    Pem(#[from] pem::PemError),

    #[error("Hardware detection error: {0}")]
    Hardware(String),

    #[error("License file too small")]
    FileTooSmall,

    #[error("Unsupported license format")]
    UnsupportedFormat,
}
