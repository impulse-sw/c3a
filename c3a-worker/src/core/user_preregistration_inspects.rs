use c3a_common::{AuthenticationData, AuthenticationRequirement, TOTPAlgorithm};
use cc_server_kit::prelude::*;

use crate::utils::{generate_numeric, hash};

pub(crate) fn gen_u2f_requirement(
  method: &AuthenticationRequirement,
  app_name: &str,
  metadata: &mut Vec<AuthenticationData>,
) {
  if matches!(method, AuthenticationRequirement::U2FKey) {
    let u2f_cli = u2f::protocol::U2f::new(app_name.to_owned());
    let challenge = u2f_cli.generate_challenge();
    metadata.push(AuthenticationData::U2F { challenge });
  }
}

pub(crate) fn gen_totp_requirement(method: &AuthenticationRequirement, metadata: &mut Vec<AuthenticationData>) {
  if let &AuthenticationRequirement::TOTPCode {
    algorithm,
    secret_length_bytes,
  } = &method
  {
    let secret = {
      use rand::{RngCore, SeedableRng, rngs::StdRng};
      let mut rng = StdRng::from_os_rng();

      let mut secret = vec![0u8; secret_length_bytes.unwrap_or(20)];
      rng.fill_bytes(&mut secret);
      totp_rs::Secret::Raw(secret)
    };

    let totp_metadata = AuthenticationData::TOTP {
      alg: algorithm.as_ref().unwrap_or(&TOTPAlgorithm::SHA1).to_string(),
      generated_secret: secret.to_encoded().to_string(),
    };

    metadata.push(totp_metadata);
  }
}

pub(crate) fn gen_email_requirement(
  method: &AuthenticationRequirement,
  id: &str,
  pepper: &[u8],
  metadata: &mut Vec<AuthenticationData>,
  mail_to_send: &mut Option<lettre::Message>,
) -> MResult<()> {
  use lettre::{Message, message::header::ContentType};

  if matches!(method, AuthenticationRequirement::EmailConfirmation) {
    let approve_code = generate_numeric(8)?;
    let (salt, hash) = hash(&approve_code, pepper)?;

    let email = Message::builder()
      .from(
        "Verbal Automation Systems - C3A <no-reply@mail.verbalautomation.tech>"
          .parse()
          .unwrap(),
      )
      .to(id.parse().unwrap())
      .subject("Email verification")
      .header(ContentType::TEXT_PLAIN)
      .body(format!("Code to confirm the account registration: {}", approve_code))
      .unwrap();

    metadata.push(AuthenticationData::Email { salt, hash });
    *mail_to_send = Some(email);

    Ok(())
  } else {
    Ok(())
  }
}
