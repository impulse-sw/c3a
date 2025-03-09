#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

mod email;
mod first_factor;

pub use crate::types::users::email::*;
pub use crate::types::users::first_factor::*;

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum AuthenticationData {
  TOTP { alg: String, generated_secret: String },
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct RegistrationRequirementsResponse {
  pub allowed_authentication_flow: Vec<UserAuthenticationRequirement>,
  pub required_authentication: Vec<UserAuthenticationRequirement>,
  pub metadata: Vec<AuthenticationData>,
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum UserAuthenticationRequirement {
  Password,
  TOTPCode,
  Question,
  EmailConfirmation,
  Proxy,
  U2FKey,
  X509Certificate,
  RawDilithium5Certificate,
  Other { description: String },
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct RegisterUserRequest {
  pub app_name: String,
  pub login: String,
  pub authentication_flows: Vec<AuthenticationFlow>,
  pub token_request_type: TokenUsageType,
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TokenUsageType {
  Cookie,
  ResponseBody,
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TokenEncryptionType {
  None,
  ChaCha20Poly1305,
}

pub type AuthenticationFlow = Vec<AuthenticationStep>;

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuthenticationStep {
  Password { password: String },
  TOTP { validation_code: String },
}
