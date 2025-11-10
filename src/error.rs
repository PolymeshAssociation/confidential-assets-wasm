use thiserror::Error;

use polymesh_api::client::Error as PolymeshClientError;

#[derive(Error, Debug)]
pub enum Error {
    /// Dart error
    #[error("Dart error: {0}")]
    DartError(#[from] polymesh_dart::Error),

    /// Polymesh client error
    #[error("Polymesh client error: {0}")]
    PolymeshClientError(String),
    //PolymeshClientError(#[from] PolymeshClientError),
    /// Other generic error
    #[error("other error: {0}")]
    Other(String),

    #[error("Json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("parity-scale-codec error: {0}")]
    ParityScaleCodec(#[from] codec::Error),

    #[error("{0} not found")]
    NotFound(String),
}

impl Error {
    pub fn other(msg: &str) -> Self {
        Self::Other(msg.to_string())
    }

    pub fn not_found(msg: &str) -> Self {
        Self::NotFound(msg.to_string())
    }
}

impl From<PolymeshClientError> for Error {
    fn from(e: PolymeshClientError) -> Self {
        Error::PolymeshClientError(e.to_string())
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
