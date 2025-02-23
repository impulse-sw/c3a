#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "c3a-worker-types")]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct GenerateInvitationRequest {
  pub private_admin_key_begin: [u8; 24],
}

/// Configuration struct for registering your application in C3A Service.
#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct AppAuthConfiguration {
  pub app_name: String,
  pub domain: String,
  pub allowed_tags: Vec<AppTag>,
  #[serde(flatten)]
  pub allow_sign_up: Option<SignUpOpts>,
  /// Generate Dilithium keypair via `pqc_dilithium::Keypair::generate`
  /// and `mode5` feature enabled, if you want to dynamically change
  /// the list of tags.
  pub author_dpub: Vec<u8>,
  pub invite: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct SignUpOpts {
  pub allow_sign_up: bool,
  pub auto_assign_tags: Vec<AppTag>,
  pub force_2fa: bool,
  pub min_login_size: Option<usize>,
  pub max_login_size: Option<usize>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct RegisteredAnswer {
  pub author_dpub: Vec<u8>,
  pub c3a_dpub: Vec<u8>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
pub struct AppTag {
  pub role: String,
  pub scope: String,
}

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
