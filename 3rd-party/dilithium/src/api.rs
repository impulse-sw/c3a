use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNBYTES};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair
{
  pub public: [u8; PUBLICKEYBYTES],
  secret: [u8; SECRETKEYBYTES],
}

/// Secret key elided
impl std::fmt::Debug for Keypair
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError
{
  Input,
  Verify,
}

pub enum RestoreError
{
  PublicKeyLen,
  SecretKeyLen,
}

impl Keypair
{
  /// Explicitly expose secret key
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// let secret_key = keys.expose_secret();
  /// assert!(secret_key.len() == SECRETKEYBYTES);
  /// ```
  pub fn expose_secret(&self) -> &[u8]
  {
    &self.secret
  }

  /// Generates a keypair for signing and verification
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// assert!(keys.public.len() == PUBLICKEYBYTES);
  /// assert!(keys.expose_secret().len() == SECRETKEYBYTES);
  /// ```
  pub fn generate() -> Keypair
  {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  /// Restores a keypair from public and secret key
  ///
  /// Example:
  /// ```rust,ignore
  /// # use pqc_dilithium::*;
  /// let (public, secret) = get_keys_from_db(&mut conn).await?;
  /// let keys = Keypair::restore(public, secret)?;
  /// ```
  pub fn restore(public: &[u8], secret: &[u8]) -> Result<Keypair, RestoreError>
  {
    if public.len() != PUBLICKEYBYTES {
      return Err(RestoreError::PublicKeyLen);
    }
    if secret.len() != SECRETKEYBYTES {
      return Err(RestoreError::SecretKeyLen);
    }

    let mut _public = [0u8; PUBLICKEYBYTES];
    let mut _secret = [0u8; SECRETKEYBYTES];
    _public[..PUBLICKEYBYTES].copy_from_slice(public);
    _secret[..SECRETKEYBYTES].copy_from_slice(secret);

    Ok(Keypair {
      public: _public,
      secret: _secret,
    })
  }

  /// Creates a keypair using the provided seed bytes.
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// let seed = [42; SEEDBYTES];
  /// let keys = Keypair::from_bytes(&seed);
  /// assert!(keys.public.len() == PUBLICKEYBYTES);
  /// assert!(keys.expose_secret().len() == SECRETKEYBYTES);
  /// ```
  pub fn from_bytes(seed: &[u8; SEEDBYTES]) -> Keypair
  {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, Some(seed));
    Keypair { public, secret }
  }

  /// Generates a signature for the given message using a keypair
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// # let keys = Keypair::generate();
  /// let msg = "Hello".as_bytes();
  /// let sig = keys.sign(&msg);
  /// assert!(sig.len() == SIGNBYTES);
  /// ```  
  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES]
  {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret);
    sig
  }
}

/// Verify signature using keypair
///
/// Example:
/// ```
/// # use pqc_dilithium::*;
/// # let keys = Keypair::generate();
/// # let msg = [0u8; 32];
/// # let sig = keys.sign(&msg);
/// let sig_verify = verify(&sig, &msg, &keys.public);
/// assert!(sig_verify.is_ok());
pub fn verify(sig: &[u8], msg: &[u8], public_key: &[u8]) -> Result<(), SignError>
{
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(sig, msg, public_key)
}
