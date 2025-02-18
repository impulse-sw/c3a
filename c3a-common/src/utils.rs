use crate::types::{MPAATHeader, MPAATPayload};

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

pub fn deploy_mpaat<T>(header: &MPAATHeader, payload: &MPAATPayload<T>) -> String {
  
}
