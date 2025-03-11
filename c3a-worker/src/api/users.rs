use c3a_common::{
  deploy_lmpaat, lmpaat_extract_payload, AuthenticationData, AuthenticationRequirement, RegisterUserRequest, RegistrationRequirementsResponse, TOTPAlgorithm, UserData
};
use cc_server_kit::prelude::*;
use serde::{Deserialize, Serialize};

use crate::kv::{KvDb, extract_db};
use crate::utils::{sign_by_header, take_exp_from_duration};

#[derive(Deserialize, Serialize)]
struct RegistrationStatePayload {
  requested_identifier: String,
  metadata: Vec<AuthenticationData>,
}

/// Application server's method.
///
/// Мы должны сперва проверить, что пользователь не зарегистрирован.
/// Если пользователь уже зарегистрирован, то мы должны вернуть ошибку.
/// Если пользователь не зарегистрирован, то мы должны вернуть список доступных методов аутентификации.
#[endpoint(tags("users"))]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn get_authentication_flow_to_register(
  depot: &mut Depot,
  req: &mut Request,
  res: &mut Response,
) -> MResult<MsgPack<RegistrationRequirementsResponse>> {
  #[derive(Deserialize)]
  struct AuthFlowQuery {
    app_name: String,
    identifier: String,
  }

  let query = req.parse_msgpack::<AuthFlowQuery>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;

  if kv.exists(&KvDb::user(&query.identifier)).await? {
    return Err(
      ErrorResponse::from("User already exists.")
        .with_403_pub()
        .build(),
    );
  }

  let app_conf = kv.get_app_conf(&query.app_name).await?;

  if app_conf.allow_sign_up.is_none() {
    return Err(
      ErrorResponse::from("Operation is not permitted by application administrator.")
        .with_403_pub()
        .build(),
    );
  }

  // TODO: Implement email verification

  let mut metadata = vec![];

  let resp = RegistrationRequirementsResponse {
    allowed_authentication_flow: app_conf
      .allow_sign_up
      .as_ref()
      .unwrap()
      .allowed_authentication_flow
      .iter()
      .inspect(|method| {
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
      })
      .inspect(|method| {
        if matches!(method, AuthenticationRequirement::U2FKey) {
          let u2f_cli = u2f::protocol::U2f::new(app_conf.app_name.to_owned());
        }
      })
      .map(|method| method.generate_user_data())
      .collect::<Vec<_>>(),
    required_authentication: app_conf
      .allow_sign_up
      .as_ref()
      .unwrap()
      .required_authentication
      .iter()
      .map(|method| method.generate_user_data())
      .collect::<Vec<_>>(),
    metadata: metadata.clone(),
  };
  let registration_state = RegistrationStatePayload { metadata, requested_identifier: query.identifier.to_owned() };

  let lmpaat = deploy_lmpaat(
    registration_state,
    None::<()>,
    take_exp_from_duration(chrono::TimeDelta::minutes(10))?,
    &app_conf.author_dpub,
    &keypair,
  )
  .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

  sign_by_header(res, &resp, &keypair)?;
  res.add_header(c3a_common::PREREGISTER_HEADER, lmpaat, true)?;

  msgpack!(resp)
}

/// Register a new user.
#[endpoint(tags("users"))]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn register(depot: &mut Depot, req: &mut Request, res: &mut Response) -> MResult<()> {
  let register_request = req.parse_msgpack::<RegisterUserRequest>().await?;
  let registration_state = req.header::<String>(c3a_common::PREREGISTER_HEADER).ok_or(
    ErrorResponse::from("No provided registration state!")
      .with_400_pub()
      .build(),
  )?;

  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  let registration_state =
    lmpaat_extract_payload::<RegistrationStatePayload, ()>(&registration_state, &keypair, chrono::Utc::now()).map_err(
      |e| {
        ErrorResponse::from(e.to_string())
          .with_400_pub()
          .with_text("No provided registration state!")
          .build()
      },
    )?;

  let app_conf = kv.get_app_conf(&register_request.app_name).await?;

  let mut user_data = UserData {
    identifier: registration_state.requested_identifier.to_owned(),
    authentication_flows: vec![],
  };

  unimplemented!()
}
