#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "c3a-worker-types")]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct GenerateInvitationRequest {
  pub private_admin_key_begin: [u8; 24],
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Debug)]
pub struct SignUpOpts {
  pub allow_sign_up: bool,
  pub auto_assign_tags: Vec<AppTag>,
  pub force_2fa: bool,
  pub min_login_size: Option<usize>,
  pub max_login_size: Option<usize>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ClientBasedAuthorizationOpts {
  pub enable_cba: bool,
  pub enable_cba_private_gateway_by: Option<AppTag>,
  pub require_cba_to_paths: Vec<String>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
pub struct AppTag {
  pub role: String,
  pub scope: String,
}

/// Configuration struct for registering your application in C3A Service.
#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct RegisterAppAuthConfigurationRequest {
  pub config: AppAuthConfiguration,
  pub invite: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct RegisterAppAuthConfigurationResponse {
  pub author_dpub: Vec<u8>,
  pub c3a_dpub: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Debug)]
pub struct AppAuthConfiguration {
  pub app_name: String,
  pub domain: String,
  pub allowed_tags: Vec<AppTag>,
  pub allow_sign_up: Option<SignUpOpts>,
  pub client_based_auth_opts: Option<ClientBasedAuthorizationOpts>,

  /// Generate Dilithium keypair via `pqc_dilithium::Keypair::generate`
  /// and `mode5` feature enabled, if you want to dynamically change
  /// the list of tags.
  pub author_dpub: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct GetAppAuthConfigurationRequest {
  pub app_name: String,
  pub author_dpub: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
pub type RemoveAppRequest = GetAppAuthConfigurationRequest;

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct GetAppAuthConfigurationResponse {
  pub config: AppAuthConfiguration,
  pub c3a_dpub: Vec<u8>,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Default)]
pub struct EditAppAuthConfigurationRequest {
  pub edit_app: String,
  pub app_name: Option<String>,
  pub domain: Option<String>,
  pub allowed_tags: Option<Vec<AppTag>>,
  pub allow_sign_up: Option<SignUpOpts>,
  pub client_based_auth_opts: Option<ClientBasedAuthorizationOpts>,
}
