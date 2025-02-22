use crate::types::{MPAATHeader, MPAATPayload, MPAATSignature};

pub fn generate_dilithium_keypair() -> pqc_dilithium::Keypair {
  pqc_dilithium::Keypair::generate()
}

pub fn restore_from(public: &[u8], secret: &[u8]) -> Result<pqc_dilithium::Keypair, pqc_dilithium::RestoreError> {
  pqc_dilithium::Keypair::restore(public, secret)
}

pub fn sign(data: &[u8], keypair: &pqc_dilithium::Keypair) -> Vec<u8> {
  keypair.sign(data).to_vec()
}

pub fn verify(data: &[u8], sign: &[u8], public_key: &[u8]) -> bool {
  pqc_dilithium::verify(sign, data, public_key).is_ok()
}

pub fn generate_chacha20poly1305_key<const SZ: usize>() -> [u8; SZ] {
  use rand::Rng;
  
  let mut arr: [u8; SZ] = [0; SZ];
  let mut rng = rand::thread_rng();
  rng.fill(arr.as_mut_slice());
  arr
}

pub enum EncryptError {
  Serialize,
  Encrypt,
}

pub fn encrypt_chacha20poly1305(message: &impl serde::Serialize, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptError> {
  use chacha20poly1305::{aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit}, consts::U32, ChaCha20Poly1305};

  let serialized = rmp_serde::to_vec(message).map_err(|_| EncryptError::Serialize)?;
  let key = GenericArray::<u8, U32>::from_slice(key);
  let cipher = ChaCha20Poly1305::new(key);
  let nonce = ChaCha20Poly1305::generate_nonce(rand::thread_rng());
  let ciphertext = cipher.encrypt(&nonce, serialized.as_ref()).map_err(|_| EncryptError::Encrypt)?;
  Ok((ciphertext, nonce.to_vec()))
}

pub enum DecryptError {
  Deserialize,
  Decrypt,
}

pub fn decrypt_chacha20poly1305<T: serde::de::DeserializeOwned>(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<T, DecryptError> {
  use chacha20poly1305::{aead::{generic_array::GenericArray, Aead, KeyInit}, consts::{U12, U32}, ChaCha20Poly1305};

  let key = GenericArray::<u8, U32>::from_slice(key);
  let cipher = ChaCha20Poly1305::new(key);
  let nonce = GenericArray::<u8, U12>::from_slice(nonce);
  let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| DecryptError::Decrypt)?;
  let deserialized = rmp_serde::from_slice::<T>(plaintext.as_slice()).map_err(|_| DecryptError::Deserialize)?;
  Ok(deserialized)
}

pub enum DeployError {
  Serialize,
  Encrypt(EncryptError),
}

pub fn deploy_mpaat<U: serde::Serialize, T: serde::Serialize>(
  payload: T,
  common_fields: Option<U>,
  exp: chrono::DateTime<chrono::Utc>,
  client_public: &[u8],
  server_enc: &[u8],
  server_keys: &pqc_dilithium::Keypair,
) -> Result<String, DeployError> {
  use base64::{engine::general_purpose::{STANDARD, URL_SAFE}, Engine as _};

  let payload = MPAATPayload { cdpub: client_public.to_vec(), container: payload };
  let (payload, nonce) = encrypt_chacha20poly1305(&payload, server_enc).map_err(|e| DeployError::Encrypt(e))?;

  let sig = MPAATSignature { sig: sign(&payload, server_keys) };
  let sig = STANDARD.encode(rmp_serde::to_vec(&sig).map_err(|_| DeployError::Serialize)?);

  let payload = URL_SAFE.encode(&payload);

  let header = MPAATHeader { sdpub: server_keys.public.to_vec(), exp, nonce, common_public_fields: common_fields };
  let header = STANDARD.encode(rmp_serde::to_vec(&header).map_err(|_| DeployError::Serialize)?);

  Ok(format!("{}.{}.{}", payload, sig, header))
}

pub enum ExtractError {
  Decode,
  Deserialize,
  Decrypt(DecryptError),
  InvalidToken,
  InvalidSignature,
  InvalidServerPublicKey,
  Expired,
}

pub fn extract_common_fields<U: serde::de::DeserializeOwned>(token: &str) -> Result<Option<U>, ExtractError> {
  use base64::{engine::general_purpose::STANDARD, Engine as _};

  let header = token.split('.').nth(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(|_| ExtractError::Decode)?;
  let header = rmp_serde::from_slice::<MPAATHeader<U>>(&header).map_err(|_| ExtractError::Deserialize)?;
  Ok(header.common_public_fields)
}

pub fn extract_payload<T, U>(
  token: &str,
  server_enc: &[u8],
  server_keys: &pqc_dilithium::Keypair,
  current_dt: chrono::DateTime<chrono::Utc>,
) -> Result<T, ExtractError>
  where
    T: serde::de::DeserializeOwned,
    U: serde::de::DeserializeOwned,
{
  use base64::{engine::general_purpose::{STANDARD, URL_SAFE}, Engine as _};

  let parts = token.split('.').collect::<Vec<_>>();

  let payload = parts.get(0).ok_or(ExtractError::InvalidToken)?;
  let payload = URL_SAFE.decode(payload).map_err(|_| ExtractError::Decode)?;

  let sig = parts.get(1).ok_or(ExtractError::InvalidToken)?;
  let sig = STANDARD.decode(sig).map_err(|_| ExtractError::Decode)?;
  let sig = rmp_serde::from_slice::<MPAATSignature>(&sig).map_err(|_| ExtractError::Deserialize)?;

  if !verify(&payload, &sig.sig, &server_keys.public) { return Err(ExtractError::InvalidSignature) }

  let header = parts.get(2).ok_or(ExtractError::InvalidToken)?;
  let header = STANDARD.decode(header).map_err(|_| ExtractError::Decode)?;
  let header = rmp_serde::from_slice::<MPAATHeader<U>>(&header).map_err(|_| ExtractError::Deserialize)?;

  if header.sdpub != server_keys.public { return Err(ExtractError::InvalidServerPublicKey) }
  if current_dt >= header.exp { return Err(ExtractError::Expired) }

  let payload = decrypt_chacha20poly1305::<MPAATPayload<T>>(&payload, &header.nonce, server_enc).map_err(|e| ExtractError::Decrypt(e))?;
  Ok(payload.container)
}
