use crate::types::{
  LightMPAATHeader, LightMPAATPayload, LightMPAATSignature, MPAATHeader, MPAATPayload, MPAATSignature,
};
use thiserror::Error;

#[cfg(feature = "pqc-utils")]
pub fn generate_dilithium_keypair() -> pqc_dilithium::Keypair {
  pqc_dilithium::Keypair::generate()
}

#[cfg(feature = "pqc-utils")]
pub fn restore_from(public: &[u8], secret: &[u8]) -> Result<pqc_dilithium::Keypair, pqc_dilithium::RestoreError> {
  pqc_dilithium::Keypair::restore(public, secret)
}

#[cfg(feature = "pqc-utils")]
#[derive(Error, Debug)]
pub enum SignError {
  #[error("Serialize error")]
  Serialize(#[from] rmp_serde::encode::Error),
}

#[cfg(feature = "pqc-utils")]
pub fn sign<T: serde::Serialize>(data: &T, keypair: &pqc_dilithium::Keypair) -> Result<Vec<u8>, SignError> {
  let data = rmp_serde::to_vec(data).map_err(SignError::Serialize)?;
  Ok(keypair.sign(&data).to_vec())
}

#[cfg(feature = "pqc-utils")]
pub fn sign_mpaat<U, T>(
  header: &MPAATHeader<U>,
  payload: &MPAATPayload<T>,
  keypair: &pqc_dilithium::Keypair,
) -> Result<Vec<u8>, SignError>
where
  U: serde::Serialize,
  T: serde::Serialize,
{
  let mut data = rmp_serde::to_vec(header).map_err(SignError::Serialize)?;
  data.extend_from_slice(&rmp_serde::to_vec(payload).map_err(SignError::Serialize)?);
  Ok(keypair.sign(&data).to_vec())
}

#[cfg(feature = "pqc-utils")]
pub fn sign_lmpaat<U, T>(
  header: &LightMPAATHeader<U>,
  payload: &LightMPAATPayload<T>,
  keypair: &pqc_dilithium::Keypair,
) -> Result<Vec<u8>, SignError>
where
  U: serde::Serialize,
  T: serde::Serialize,
{
  let mut data = rmp_serde::to_vec(header).map_err(SignError::Serialize)?;
  data.extend_from_slice(&rmp_serde::to_vec(payload).map_err(SignError::Serialize)?);
  Ok(keypair.sign(&data).to_vec())
}

#[cfg(feature = "pqc-utils")]
#[derive(Error, Debug)]
pub enum VerifyError {
  #[error("Serialize error")]
  Serialize(#[from] rmp_serde::encode::Error),
}

#[cfg(feature = "pqc-utils")]
pub fn verify<T: serde::Serialize>(data: &T, sign: &[u8], public_key: &[u8]) -> Result<bool, VerifyError> {
  let data = rmp_serde::to_vec(data).map_err(VerifyError::Serialize)?;
  Ok(pqc_dilithium::verify(sign, &data, public_key).is_ok())
}

#[cfg(feature = "pqc-utils")]
pub fn verify_token(header: &[u8], payload: &[u8], sign: &[u8], public_key: &[u8]) -> Result<bool, VerifyError> {
  let mut data = header.to_vec();
  data.extend_from_slice(payload);
  Ok(pqc_dilithium::verify(sign, &data, public_key).is_ok())
}

pub fn base64_encode(data: &[u8]) -> String {
  use base64::{Engine as _, engine::general_purpose::URL_SAFE};
  URL_SAFE.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
  use base64::{Engine as _, engine::general_purpose::URL_SAFE};
  URL_SAFE.decode(data)
}

#[cfg(feature = "crypt-utils")]
pub fn generate_chacha20poly1305_key() -> [u8; 256] {
  use rand::Rng;

  let mut arr: [u8; 256] = [0; 256];
  let mut rng = rand::rng();
  rng.fill(arr.as_mut_slice());
  arr
}

#[cfg(feature = "crypt-utils")]
pub fn generate<const SZ: usize>() -> [u8; SZ] {
  use rand::Rng;

  let mut arr: [u8; SZ] = [0; SZ];
  let mut rng = rand::rng();
  rng.fill(arr.as_mut_slice());
  arr
}

#[derive(Error, Debug)]
pub enum EncryptError {
  #[error("Serialize error")]
  Serialize(#[from] rmp_serde::encode::Error),
  #[error("Encrypt error")]
  Encrypt,
}

pub fn encrypt_chacha20poly1305(
  message: &impl serde::Serialize,
  key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EncryptError> {
  use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, generic_array::GenericArray},
    consts::U32,
  };

  let serialized = rmp_serde::to_vec(message).map_err(EncryptError::Serialize)?;
  let key = GenericArray::<u8, U32>::from_slice(key);
  let cipher = ChaCha20Poly1305::new(key);
  let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
  let ciphertext = cipher
    .encrypt(&nonce, serialized.as_ref())
    .map_err(|_| EncryptError::Encrypt)?;
  Ok((ciphertext, nonce.to_vec()))
}

#[derive(Error, Debug)]
pub enum DecryptError {
  #[error("Deserialize error")]
  Deserialize(#[from] rmp_serde::decode::Error),
  #[error("Decrypt error")]
  Decrypt,
}

pub fn decrypt_chacha20poly1305<T: serde::de::DeserializeOwned>(
  ciphertext: &[u8],
  key: &[u8],
  nonce: &[u8],
) -> Result<T, DecryptError> {
  use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, generic_array::GenericArray},
    consts::{U12, U32},
  };

  let key = GenericArray::<u8, U32>::from_slice(key);
  let cipher = ChaCha20Poly1305::new(key);
  let nonce = GenericArray::<u8, U12>::from_slice(nonce);
  let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| DecryptError::Decrypt)?;
  let deserialized = rmp_serde::from_slice::<T>(plaintext.as_slice()).map_err(DecryptError::Deserialize)?;
  Ok(deserialized)
}

#[cfg(feature = "pqc-utils")]
#[derive(Error, Debug)]
pub enum DeployError {
  #[error("Serialize error")]
  Serialize(#[from] rmp_serde::encode::Error),
  #[error("Encrypt error")]
  Encrypt(#[from] EncryptError),
  #[error("Sign error")]
  Sign(#[from] SignError),
}

#[cfg(feature = "pqc-utils")]
pub fn deploy_mpaat<U: serde::Serialize, T: serde::Serialize>(
  payload: T,
  common_fields: Option<U>,
  exp: chrono::DateTime<chrono::Utc>,
  client_public: &[u8],
  server_enc: Option<&[u8]>,
  server_keys: &pqc_dilithium::Keypair,
) -> Result<String, DeployError> {
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let payload = MPAATPayload {
    cdpub: client_public.to_vec(),
    exp,
    container: payload,
  };
  let (enc_payload, nonce) = if let Some(server_enc) = server_enc {
    encrypt_chacha20poly1305(&payload, server_enc).map_err(DeployError::Encrypt)?
  } else {
    (rmp_serde::to_vec(&payload).map_err(EncryptError::Serialize)?, vec![])
  };

  let enc_payload = URL_SAFE.encode(&enc_payload);

  let header = MPAATHeader {
    sdpub: server_keys.public.to_vec(),
    nonce,
    common_public_fields: common_fields,
  };

  let sig = MPAATSignature {
    sig: sign_mpaat(&header, &payload, server_keys).map_err(DeployError::Sign)?,
  };
  let sig = STANDARD.encode(rmp_serde::to_vec(&sig).map_err(DeployError::Serialize)?);

  let header = STANDARD.encode(rmp_serde::to_vec(&header).map_err(DeployError::Serialize)?);

  Ok(format!("{}.{}.{}", enc_payload, sig, header))
}

#[cfg(feature = "pqc-utils")]
pub fn deploy_lmpaat<U: serde::Serialize, T: serde::Serialize>(
  payload: T,
  common_fields: Option<U>,
  exp: chrono::DateTime<chrono::Utc>,
  client_public: &[u8],
  server_keys: &pqc_dilithium::Keypair,
) -> Result<String, DeployError> {
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let payload = LightMPAATPayload {
    exp,
    container: payload,
  };
  let enc_payload = rmp_serde::to_vec(&payload).map_err(EncryptError::Serialize)?;
  let enc_payload = URL_SAFE.encode(&enc_payload);

  let header = LightMPAATHeader {
    cdpub: client_public.to_vec(),
    common_public_fields: common_fields,
  };

  let sig = MPAATSignature {
    sig: sign_lmpaat(&header, &payload, server_keys).map_err(DeployError::Sign)?,
  };
  let sig = STANDARD.encode(rmp_serde::to_vec(&sig).map_err(DeployError::Serialize)?);

  let header = STANDARD.encode(rmp_serde::to_vec(&header).map_err(DeployError::Serialize)?);

  Ok(format!("{}.{}.{}", enc_payload, sig, header))
}

#[cfg(feature = "pqc-utils")]
#[derive(Error, Debug)]
pub enum ExtractError {
  #[error("Decode error")]
  Decode(#[from] base64::DecodeError),
  #[error("Deserialize error")]
  Deserialize(#[from] rmp_serde::decode::Error),
  #[error("Decrypt error")]
  Decrypt(#[from] DecryptError),
  #[error("Verify error")]
  Verify(#[from] VerifyError),
  #[error("Invalid token error")]
  InvalidToken,
  #[error("Invalid signature error")]
  InvalidSignature,
  #[error("Invalid server public key error")]
  InvalidServerPublicKey,
  #[error("Expired error")]
  Expired,
}

pub fn mpaat_extract_common_fields<U: serde::de::DeserializeOwned>(
  token: &str,
  server_keys: &pqc_dilithium::Keypair,
) -> Result<Option<U>, ExtractError> {
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let parts = token.split('.').collect::<Vec<_>>();

  let sig = parts.get(1).ok_or(ExtractError::InvalidToken)?;
  let sig = STANDARD.decode(sig).map_err(ExtractError::Decode)?;
  let sig = rmp_serde::from_slice::<MPAATSignature>(&sig).map_err(ExtractError::Deserialize)?;

  let payload = parts.first().ok_or(ExtractError::InvalidToken)?;
  let payload = URL_SAFE.decode(payload).map_err(ExtractError::Decode)?;

  let header = parts.get(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(ExtractError::Decode)?;

  if !verify_token(&header, &payload, &sig.sig, &server_keys.public).map_err(ExtractError::Verify)? {
    return Err(ExtractError::InvalidSignature);
  }

  let header = rmp_serde::from_slice::<MPAATHeader<U>>(&header).map_err(ExtractError::Deserialize)?;
  if header.sdpub != server_keys.public {
    return Err(ExtractError::InvalidServerPublicKey);
  }

  Ok(header.common_public_fields)
}

#[cfg(feature = "pqc-utils")]
pub fn mpaat_extract_payload<T, U>(
  token: &str,
  server_enc: Option<&[u8]>,
  server_keys: &pqc_dilithium::Keypair,
  current_dt: chrono::DateTime<chrono::Utc>,
) -> Result<T, ExtractError>
where
  T: serde::de::DeserializeOwned,
  U: serde::de::DeserializeOwned,
{
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let parts = token.split('.').collect::<Vec<_>>();

  let sig = parts.get(1).ok_or(ExtractError::InvalidToken)?;
  let sig = STANDARD.decode(sig).map_err(ExtractError::Decode)?;
  let sig = rmp_serde::from_slice::<MPAATSignature>(&sig).map_err(ExtractError::Deserialize)?;

  let payload = parts.first().ok_or(ExtractError::InvalidToken)?;
  let payload = URL_SAFE.decode(payload).map_err(ExtractError::Decode)?;

  let header = parts.get(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(ExtractError::Decode)?;

  if !verify_token(&header, &payload, &sig.sig, &server_keys.public).map_err(ExtractError::Verify)? {
    return Err(ExtractError::InvalidSignature);
  }

  let header = rmp_serde::from_slice::<MPAATHeader<U>>(&header).map_err(ExtractError::Deserialize)?;
  if header.sdpub != server_keys.public {
    return Err(ExtractError::InvalidServerPublicKey);
  }

  let payload = if let Some(server_enc) = server_enc {
    decrypt_chacha20poly1305::<MPAATPayload<T>>(&payload, &header.nonce, server_enc).map_err(ExtractError::Decrypt)?
  } else {
    rmp_serde::from_slice::<MPAATPayload<T>>(&payload).map_err(ExtractError::Deserialize)?
  };

  if current_dt >= payload.exp {
    return Err(ExtractError::Expired);
  }

  Ok(payload.container)
}

pub fn lmpaat_extract_common_fields<U: serde::de::DeserializeOwned>(
  token: &str,
  server_keys: &pqc_dilithium::Keypair,
) -> Result<Option<U>, ExtractError> {
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let parts = token.split('.').collect::<Vec<_>>();

  let sig = parts.get(1).ok_or(ExtractError::InvalidToken)?;
  let sig = STANDARD.decode(sig).map_err(ExtractError::Decode)?;
  let sig = rmp_serde::from_slice::<LightMPAATSignature>(&sig).map_err(ExtractError::Deserialize)?;

  let payload = parts.first().ok_or(ExtractError::InvalidToken)?;
  let payload = URL_SAFE.decode(payload).map_err(ExtractError::Decode)?;

  let header = parts.get(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(ExtractError::Decode)?;

  if !verify_token(&header, &payload, &sig.sig, &server_keys.public).map_err(ExtractError::Verify)? {
    return Err(ExtractError::InvalidSignature);
  }

  let header = rmp_serde::from_slice::<LightMPAATHeader<U>>(&header).map_err(ExtractError::Deserialize)?;
  Ok(header.common_public_fields)
}

#[cfg(feature = "pqc-utils")]
pub fn lmpaat_extract_payload<T, U>(
  token: &str,
  server_keys: &pqc_dilithium::Keypair,
  current_dt: chrono::DateTime<chrono::Utc>,
) -> Result<T, ExtractError>
where
  T: serde::de::DeserializeOwned,
  U: serde::de::DeserializeOwned,
{
  use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
  };

  let parts = token.split('.').collect::<Vec<_>>();

  let sig = parts.get(1).ok_or(ExtractError::InvalidToken)?;
  let sig = STANDARD.decode(sig).map_err(ExtractError::Decode)?;
  let sig = rmp_serde::from_slice::<LightMPAATSignature>(&sig).map_err(ExtractError::Deserialize)?;

  let payload = parts.first().ok_or(ExtractError::InvalidToken)?;
  let payload = URL_SAFE.decode(payload).map_err(ExtractError::Decode)?;

  let header = parts.get(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(ExtractError::Decode)?;

  if !verify_token(&header, &payload, &sig.sig, &server_keys.public).map_err(ExtractError::Verify)? {
    return Err(ExtractError::InvalidSignature);
  }

  let payload = rmp_serde::from_slice::<LightMPAATPayload<T>>(&payload).map_err(ExtractError::Deserialize)?;
  if current_dt >= payload.exp {
    return Err(ExtractError::Expired);
  }

  Ok(payload.container)
}
