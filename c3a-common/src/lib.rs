use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct AppAuthConfiguration {
  pub app_name: String,
  pub domain: String,
  pub allowed_tags: Vec<AppTag>,
  #[serde(flatten)]
  pub allow_sign_up: Option<SignUpOpts>,
  /// Generate Dilithium keypair via `pqc_dilithium::Keypair::generate`
  /// and `mode5` feature enabled, if you want to dynamically change
  /// the list of tags.
  pub author_dpub: Option<Vec<u8>>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct SignUpOpts {
  pub allow_sign_up: bool,
  pub auto_assign_tags: Vec<AppTag>,
  pub force_2fa: bool,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct AppTag {
  pub role: String,
  pub scope: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct RegisteredAppKey

/// MessagePack-based Application Authority Token
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAAT<T> {
  pub header: MPAATHeader,
  pub payload: MPAATPayload<T>,
  pub signature: MPAATSignature,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATHeader {
  pub sdpub: Vec<u8>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATPayload<T> {
  pub cdpub: Vec<u8>,
  #[serde(flatten)]
  pub container: T,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct MPAATSignature {
  pub sig: Vec<u8>,
}
