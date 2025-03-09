#[cfg(any(feature = "app-server-types", feature = "c3a-worker-types"))]
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[cfg_attr(any(feature = "app-server-types", feature = "c3a-worker-types"), derive(ToSchema))]
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Email(String);

#[derive(thiserror::Error, Debug)]
pub enum EmailError {
  #[error("Invalid email")]
  Invalid,
}

impl Email {
  fn validate(email: &str) -> bool {
    let email_regex = regex::Regex::new(r"^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4})$").unwrap();

    email_regex.is_match(email)
      && !email.contains("..")
      && !email.starts_with('.')
      && !email.ends_with('.')
      && email.matches('@').count() == 1
  }

  pub fn new(email: impl AsRef<str>) -> Result<Self, EmailError> {
    if !Email::validate(email.as_ref()) {
      Err(EmailError::Invalid)
    } else {
      Ok(Self(email.as_ref().to_owned()))
    }
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
    if Email::validate(value) {
      Ok(Email(value.to_string()))
    } else {
      Err(E::custom(format!("invalid email address: {}", value)))
    }
  }
}
