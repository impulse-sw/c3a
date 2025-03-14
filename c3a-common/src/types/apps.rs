use chrono::Duration;
#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::types::users::{IdenticationRequirement, TokenEncryptionType, UserAuthenticationRequirement};

#[cfg(feature = "c3a-worker-types")]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone)]
pub struct GenerateInvitationRequest {
  pub private_admin_key_begin: [u8; 24],
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Debug)]
pub struct SignUpOpts {
  pub identify_by: IdenticationRequirement,
  pub allow_sign_up: bool,
  pub auto_assign_tags: Vec<AppTag>,
  pub allowed_authentication_flow: Vec<AuthenticationRequirement>,
  pub required_authentication: Vec<AuthenticationRequirement>,
  /// User can choose alternative authentication requirements' data
  /// to redirect application on honeypots - just clear enough accounts.
  ///
  /// Authentication flow will be the same, user may just enter another
  /// predefined data such as second variant' passwords to activate honeypot.
  pub allow_honeypots: bool,
  /// Ban (permanently or temporarily) on unsuccessful attempts.
  pub enable_fail_to_ban: Option<Fail2BanOptions>,
  /// Allows the user to view and save a 256-symbol recovery key once.
  ///
  /// This key will discontinue all refresh tokens and will lead to changing
  /// authentication flow data (at least one used factor).
  pub allow_recovery_key: bool,
  pub token_encryption_type: TokenEncryptionType,
}

#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
#[derive(Deserialize, Serialize, ToSchema, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ClientBasedAuthorizationOpts {
  pub enable_cba: bool,
  pub enable_cba_private_gateway_by: Option<AppTag>,
  pub require_cba_to_paths: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
pub struct AppTag {
  pub role: String,
  pub scope: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TOTPAlgorithm {
  SHA1,
  SHA256,
  SHA512,
}

impl TOTPAlgorithm {
  pub fn into_totp_rs(&self) -> totp_rs::Algorithm {
    match self {
      Self::SHA1 => totp_rs::Algorithm::SHA1,
      Self::SHA256 => totp_rs::Algorithm::SHA256,
      Self::SHA512 => totp_rs::Algorithm::SHA512,
    }
  }
}

impl std::fmt::Display for TOTPAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::SHA1 => f.write_str("SHA1"),
      Self::SHA256 => f.write_str("SHA256"),
      Self::SHA512 => f.write_str("SHA512"),
    }
  }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuthenticationRequirement {
  Password {
    min_size: usize,
    should_contain_different_case: bool,
    should_contain_symbols: bool,
  },

  /// Standard TOTP 2FA.
  ///
  /// Default algorithm is `SHA1`, default length in bytes - 20 (160 bits).
  ///
  /// It's recommended to use `SHA256`/`SHA512` and 32 bytes of secret, if your
  /// 2FA application supports this.
  ///
  /// Other parameters: 6 digits, 1 skew step, 30 seconds to step.
  ///
  /// Related RFC:
  ///
  /// - [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
  /// - [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)
  ///
  /// Rust realization: [`totp-rs`](https://docs.rs/totp-rs).
  TOTPCode {
    algorithm: Option<TOTPAlgorithm>,
    secret_length_bytes: Option<usize>,
  },
  Question,
  EmailConfirmation,

  /// Direct identication of IP addresses is available only when using the client API.
  ///
  /// On server authentication flow API you should identicate user IP address by yourself.
  Proxy {
    allowed_ip_addresses: Vec<IpAddr>,
  },

  U2FKey,

  /// Allowed signature algorithms:
  ///
  /// 1. `RSA_PKCS1_2048_8192_SHA256`
  /// 2. `RSA_PKCS1_2048_8192_SHA384`
  /// 3. `RSA_PKCS1_2048_8192_SHA512`
  /// 4. `ECDSA_P256_SHA256_ASN1`
  /// 5. `ECDSA_P384_SHA384_ASN1`
  /// 6. `ED25519`
  X509Certificate {
    validation: X509CertificateValidationRequirement,
  },

  RawDilithium5Certificate {
    validation: Dilithium5RawCertificateValidationRequirement,
  },

  /// See [this](https://www.jetbrains.com/help/idea/exploring-http-syntax.html).
  ///
  /// Please, provide complete description without any external files.
  /// If the request returns 200, authentication completes successfully.
  ///
  /// These placeholders will be replaced:
  /// 1. `C3A-Application-Name` - with `app_name`.
  /// 2. `C3A-Domain` - with `domain`.
  /// 3. `C3A-User-ID` - with actual user ID.
  /// 4. `C3A-Authentication-Flow-Json` or `C3A-Authentication-Flow-Json-Base64` - with authentication flow description.
  Other {
    http_rest_description: String,
    description_to_user: String,
  },
}

impl AuthenticationRequirement {
  pub fn generate_user_data(&self) -> UserAuthenticationRequirement {
    match self {
      Self::Password { .. } => UserAuthenticationRequirement::Password,
      Self::TOTPCode { .. } => UserAuthenticationRequirement::TOTPCode,
      Self::Question => UserAuthenticationRequirement::Question,
      Self::EmailConfirmation => UserAuthenticationRequirement::EmailConfirmation,
      Self::Proxy { .. } => UserAuthenticationRequirement::Proxy,
      Self::U2FKey => UserAuthenticationRequirement::U2FKey,
      Self::X509Certificate { .. } => UserAuthenticationRequirement::X509Certificate,
      Self::RawDilithium5Certificate { .. } => UserAuthenticationRequirement::RawDilithium5Certificate,
      Self::Other {
        description_to_user, ..
      } => UserAuthenticationRequirement::Other {
        description: description_to_user.to_owned(),
      },
    }
  }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum X509CertificateValidationRequirement {
  /// You can allow the usage of self-signed certificates during the authentication flow
  /// when the public keys is equal to ones stored on registration.
  SelfSigned,

  /// You can allow the usage of certificates during the authentication flow
  /// when they are issued by provided issuers.
  SignedByOneOfIssuers { allowed_issuers_pem: Vec<Vec<u8>> },
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Dilithium5RawCertificateValidationRequirement {
  /// You can allow the usage of raw unsigned public keys during the authentication flow
  /// when they are equal to ones stored on registration.
  Unsigned,

  /// You can allow the usage of raw public keys during the authentication flow
  /// when they have valid signatures signed by one of provided issuer.
  SignedByOneOfIssuers {
    allowed_issuers_raw_public_keys: Vec<Vec<u8>>,
  },
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
pub struct Fail2BanOptions {
  pub max_allowed_unsuccessful_attempts: usize,
  pub ban_login_expiration: Duration,
  pub ban_ip: bool,
  pub ban_ip_expiration: Option<Duration>,
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
