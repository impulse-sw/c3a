use argon2::PasswordVerifier;
use cc_server_kit::prelude::{ErrorResponse, MResult};

pub(crate) fn hash(value: &str, pepper: &[u8]) -> MResult<(String, Vec<u8>)> {
  use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
  };

  let mut peppered = value.as_bytes().to_vec();
  peppered.extend_from_slice(pepper);

  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();
  let phash = argon2
    .hash_password(&peppered, &salt)
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
  let (salt, hash) = Argon2::export(&phash).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

  Ok((salt, hash))
}

#[allow(dead_code)]
pub(crate) fn validate_hash(value: &str, salt: &str, hash: &[u8], pepper: &[u8]) -> MResult<()> {
  let mut peppered = value.as_bytes().to_vec();
  peppered.extend_from_slice(pepper);

  let argon2 = argon2::Argon2::default();
  let phash = argon2
    .import(salt, hash)
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
  argon2
    .verify_password(&peppered, &phash)
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())
}

#[cfg(test)]
mod tests {
  use super::{hash, validate_hash};

  #[test]
  fn test_hash_and_verify() {
    let password = "hello world!";
    let pepper = b"some pepper";

    let (salt, hash) = hash(password, pepper).unwrap();
    assert!(validate_hash(password, &salt, &hash, pepper).is_ok())
  }
}
