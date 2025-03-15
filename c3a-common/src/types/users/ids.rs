#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Debug)]
#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IdenticationRequirement {
  /// Simple nickname identication.
  ///
  /// You can specify:
  /// 1. Allowance of spaces (e.g., `pimple crawler`)
  /// 2. Allowance of upper-registry letters (e.g., `HelloKitty1983`)
  /// 3. Allowance of characters except `_` & `-` (e.g., `MainForce **ELIGE**`)
  Nickname {
    spaces: bool,
    upper_registry: bool,
    characters: bool,
  },

  /// Email identication.
  ///
  /// You can specify email domains that you want to exclude
  /// (for example, that domains which supports temporary registration).
  Email { exclude_email_domains: Vec<String> },
}

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Email(String);

#[derive(thiserror::Error, Debug)]
pub enum EmailError {
  #[error("Invalid email")]
  Invalid,
}

impl Email {
  fn validate(email: &str) -> Result<(), EmailError> {
    let email_regex = regex::Regex::new(r"^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10})$").unwrap();
    if email_regex.is_match(email) && !email.contains("..") && !email.starts_with('.') {
      Ok(())
    } else {
      Err(EmailError::Invalid)
    }
  }

  pub fn new(email: impl AsRef<str>) -> Result<Self, EmailError> {
    Email::validate(email.as_ref())?;
    Ok(Self(email.as_ref().to_owned()))
  }

  pub fn domain(&self) -> &str {
    self.0.split('@').next_back().unwrap()
  }
}

impl Serialize for Email {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(&self.0)
  }
}

impl<'de> Deserialize<'de> for Email {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_str(EmailVisitor)
  }
}

struct EmailVisitor;

impl<'de> serde::de::Visitor<'de> for EmailVisitor {
  type Value = Email;

  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str("a valid email address")
  }

  fn visit_str<E>(self, value: &str) -> Result<Email, E>
  where
    E: serde::de::Error,
  {
    if Email::validate(value).is_ok() {
      Ok(Email(value.to_string()))
    } else {
      Err(E::custom(format!("invalid email address: {}", value)))
    }
  }
}
