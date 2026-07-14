//! Crate-wide error type.

/// Errors that can occur during a transfer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame encoding: {0}")]
    Json(#[from] serde_json::Error),

    /// Peer violated the control protocol (bad frame, wrong version, ...).
    #[error("protocol: {0}")]
    Protocol(String),

    /// Transfer finished but something is wrong with the result.
    #[error("transfer failed: {0}")]
    Transfer(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
}
