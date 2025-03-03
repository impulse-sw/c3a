#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(tag = "type")]
pub enum FirstFactor {
  Password { password: String },
  Question { question: String, answer: String },
  TOTPCode { existing_totp_key: String },
}
