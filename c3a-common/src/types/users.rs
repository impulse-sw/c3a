#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

mod ids;

pub use crate::types::users::ids::*;

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum AuthenticationData {
  TOTP { alg: String, generated_secret: String },
  U2F { challenge: u2f::protocol::Challenge },
  Email { salt: String, hash: Vec<u8> },
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
  pub authentication_flows: Vec<AuthenticationFlowRequest>,
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

pub type AuthenticationFlowRequest = Vec<AuthenticationStepRequest>;

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuthenticationStepRequest {
  Password { password: String },
  TOTPCode { validation_code: String },
  Question { question: String, answer: String },
  EmailConfirmation { code: String },
  Proxy,
  U2FKey { accepted_challenge: Vec<u8> },
  X509Certificate { public_certificate: Vec<u8> },
  RawDilithium5Certificate { public_key: Vec<u8> },
  Other,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct UserData {
  /// Email or username
  pub identifier: String,
  /// Authentication flows
  pub authentication_flows: Vec<AuthenticationFlow>,
}

pub type AuthenticationFlow = Vec<AuthenticationStep>;

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuthenticationStep {
  Password {
    salt: Vec<u8>,
    hash: Vec<u8>,
  },
  TOTPCode {
    secret: String,
  },
  Question {
    question: String,
    salt: Vec<u8>,
    hash: Vec<u8>,
  },
  EmailConfirmation,
  Proxy,
  U2FKey {
    registration: u2f::register::Registration,
  },
  X509Certificate {
    public_certificate: Vec<u8>,
  },
  RawDilithium5Certificate {
    public_key: Vec<u8>,
  },
  Other,
}
