use c3a_common::{
  AppAuthConfiguration, AuthenticationData, AuthenticationRequirement, RegisterUserRequest,
  RegistrationRequirementsResponse, TOTPAlgorithm, deploy_lmpaat, lmpaat_extract_payload,
};
use cc_server_kit::prelude::*;
use serde::{Deserialize, Serialize};

use crate::kv::{KvDb, extract_db};
use crate::utils::{sign_by_header, take_exp_from_duration};

#[derive(Deserialize, Serialize)]
struct RegistrationStatePayload {
  metadata: Vec<AuthenticationData>,
}

/// Application server's method.
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
  }

  let query = req.parse_queries::<AuthFlowQuery>()?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;

  let app_conf = kv
    .get::<AppAuthConfiguration>(&KvDb::app(&query.app_name))
    .await?
    .ok_or(ErrorResponse::from("There is no such app.").with_404_pub().build())?;

  if app_conf.allow_sign_up.is_none() {
    return Err(
      ErrorResponse::from("Operation is not permitted by application administrator.")
        .with_403_pub()
        .build(),
    );
  }

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
            use rand::Rng;

            let mut rng = rand::thread_rng();
            let mut secret = vec![0u8; secret_length_bytes.unwrap_or(20)];
            rng.fill(&mut secret[..]);
            totp_rs::Secret::Raw(secret)
          };

          let totp_metadata = AuthenticationData::TOTP {
            alg: algorithm.as_ref().unwrap_or(&TOTPAlgorithm::SHA1).to_string(),
            generated_secret: secret.to_encoded().to_string(),
          };

          metadata.push(totp_metadata);
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
  let registration_state = RegistrationStatePayload { metadata };

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

#[endpoint(tags("users"))]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn register(depot: &mut Depot, req: &mut Request, _res: &mut Response) -> MResult<()> {
  let _register_request = req.parse_msgpack::<RegisterUserRequest>().await?;
  let registration_state = req.header::<String>(c3a_common::PREREGISTER_HEADER).ok_or(
    ErrorResponse::from("No provided registration state!")
      .with_400_pub()
      .build(),
  )?;

  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  let _registration_state =
    lmpaat_extract_payload::<RegistrationStatePayload, ()>(&registration_state, &keypair, chrono::Utc::now()).map_err(
      |e| {
        ErrorResponse::from(e.to_string())
          .with_400_pub()
          .with_text("No provided registration state!")
          .build()
      },
    )?;

  unimplemented!()
}
