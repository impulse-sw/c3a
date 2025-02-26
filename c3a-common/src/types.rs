#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
mod apps;

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
pub use apps::*;

use serde::{Deserialize, Serialize};

/// MessagePack-based Application Authority Token
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAAT<U, T> {
  pub header: MPAATHeader<U>,
  pub payload: MPAATPayload<T>,
  pub signature: MPAATSignature,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATHeader<U> {
  pub sdpub: Vec<u8>,
  pub nonce: Vec<u8>,
  #[serde(flatten)]
  pub common_public_fields: Option<U>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATPayload<T> {
  pub cdpub: Vec<u8>,
  pub exp: chrono::DateTime<chrono::Utc>,
  #[serde(flatten)]
  pub container: T,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATSignature {
  pub sig: Vec<u8>,
}
