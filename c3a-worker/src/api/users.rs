use c3a_common::{
  AuthenticationData, RegisterUserRequest, RegistrationRequirementsResponse, UserData, deploy_lmpaat,
  lmpaat_extract_payload, validate_identifier,
};
use cc_server_kit::prelude::*;
use lettre::AsyncTransport;
use serde::{Deserialize, Serialize};

use crate::core::user_registration_checks::validate_authentication_flows;
use crate::Setup;
use crate::core::user_preregistration_inspects::{gen_email_requirement, gen_totp_requirement, gen_u2f_requirement};
use crate::kv::{KvDb, extract_db};
use crate::mailer::extract_mailer;
use crate::utils::{sign_by_header, take_exp_from_duration};

#[derive(Deserialize, Serialize)]
pub(crate) struct RegistrationStatePayload {
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
  let mailer = extract_mailer(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  let c3a_state = depot.obtain::<Setup>()?;

  if kv.exists(&KvDb::user(&query.identifier)).await? {
    return Err(ErrorResponse::from("User already exists.").with_403_pub().build());
  }

  let app_conf = kv.get_app_conf(&query.app_name).await?;
  match &app_conf.allow_sign_up {
    None => {
      return Err(
        ErrorResponse::from("Operation is not permitted by application administrator.")
          .with_403_pub()
          .build(),
      );
    }
    Some(opts) => validate_identifier(&opts.identify_by, &query.identifier)
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500_pub().build())?,
  }

  let mut metadata = vec![];
  let mut inspect_err = Ok(());
  let mut mail_to_send = None;

  let resp = RegistrationRequirementsResponse {
    allowed_authentication_flow: app_conf
      .allow_sign_up
      .as_ref()
      .unwrap()
      .allowed_authentication_flow
      .iter()
      .inspect(|method| {
        gen_totp_requirement(method, &mut metadata);
        gen_u2f_requirement(method, &app_conf.app_name, &mut metadata);
        if let Err(e) = gen_email_requirement(
          method,
          &query.identifier,
          &c3a_state.private_adm_key.as_ref().unwrap().as_bytes()[24..=48],
          &mut metadata,
          &mut mail_to_send,
        ) {
          inspect_err = Err(e);
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

  inspect_err?;
  if let Some(email) = mail_to_send {
    mailer
      .send(email)
      .await
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
  }

  let registration_state = RegistrationStatePayload {
    metadata,
    requested_identifier: query.identifier.to_owned(),
  };

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
    ErrorResponse::from("No provided registration state!").with_400_pub().build()
  )?;

  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  
  let app_conf = kv.get_app_conf(&register_request.app_name).await?;
  if app_conf.allow_sign_up.is_none() {
    return Err(ErrorResponse::from("Operation is not permitted by application administrator.").with_403_pub().build())
  }
  
  let registration_state =
    lmpaat_extract_payload::<RegistrationStatePayload, ()>(&registration_state, &keypair, chrono::Utc::now())
      .map_err(|e| ErrorResponse::from(e.to_string()).with_400_pub().with_text("No provided registration state!").build())?;

  let user_data = UserData {
    identifier: registration_state.requested_identifier.to_owned(),
    authentication_flows: validate_authentication_flows(
      registration_state,
      &register_request.authentication_flows,
      app_conf.allow_sign_up.as_ref().unwrap(),
    )?,
  };
  
  
  

  Ok(())
}
