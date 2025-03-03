#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

mod email;
mod first_factor;

pub use crate::types::users::email::*;
pub use crate::types::users::first_factor::*;

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct RegisterUserRequest {
  pub login: Email,
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct RegisterUserResponse {}
