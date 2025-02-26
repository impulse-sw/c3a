use c3a_common::{
  generate,
  AppAuthConfiguration,
  GenerateInvitationRequest,
  GetAppAuthConfigurationRequest,
  GetAppAuthConfigurationResponse,
  RegisterAppAuthConfigurationRequest,
  RegisterAppAuthConfigurationResponse,
};
use cc_server_kit::{prelude::*, salvo::Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
  kv::{extract_db, KvDb},
  utils::{sign_by_header, verify_sign_by_header},
  Setup,
};

/// Service availability check.
#[endpoint(
  tags("maintenance"),
  responses((status_code = 200, description = "Service availability check result"))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
#[allow(unused_braces)]
async fn health_check(req: &mut Request) -> MResult<OK> { return ok!() }

#[derive(Deserialize, Serialize, Default)]
struct Invitations {
  invitations: HashSet<Vec<u8>>,
}

#[handler]
async fn generate_invitation(req: &mut Request, depot: &mut Depot) -> MResult<MsgPack<Vec<u8>>> {
  let request = req.parse_msgpack::<GenerateInvitationRequest>().await?;
  let kv = extract_db(depot)?;
  let c3a_state = depot.obtain::<Setup>()?;
  
  if c3a_state.private_adm_key.as_ref().unwrap().as_bytes()[..24] != request.private_admin_key_begin {
    return Err(ErrorResponse::from("Invalid authentication request").with_401_pub().build())
  }
  
  let mut invitations = kv.get::<Invitations>(KvDb::INVITES).await?.unwrap_or_default();
  let new_invite = generate::<1024>().to_vec();
  invitations.invitations.insert(new_invite.clone());
  kv.upsert(KvDb::INVITES, &invitations).await?;
  
  msgpack!(new_invite)
}

/// Register service.
/// 
/// To register your service, you should have service backend to send this options once on start.
#[endpoint(
  tags("maintenance"),
  responses((
    status_code = 200,
    description = "Service availability check result",
    body = RegisterAppAuthConfigurationResponse,
    content_type = ["application/msgpack"]
  ))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn service_register(req: &mut Request, res: &mut Response, depot: &mut Depot) -> MResult<MsgPack<RegisterAppAuthConfigurationResponse>> {
  let request = req.parse_msgpack::<RegisterAppAuthConfigurationRequest>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  
  verify_sign_by_header(req, &request, &request.config.author_dpub)?;
  
  let mut invitations = kv.get::<Invitations>(KvDb::INVITES).await?.unwrap_or_default();
  if !invitations.invitations.contains(&request.invite) {
    return Err(ErrorResponse::from("Your invitation code is invalid!").with_401_pub().build())
  }
  invitations.invitations.remove(&request.invite);
  kv.upsert(KvDb::INVITES, &invitations).await?;
  
  let app_conf = request.config;
  kv.insert(&KvDb::app(&app_conf.app_name), &app_conf).await?;
  
  let answer = RegisterAppAuthConfigurationResponse { author_dpub: app_conf.author_dpub, c3a_dpub: keypair.public.to_vec() };
  sign_by_header(res, &answer, &keypair)?;
  
  msgpack!(answer)
}

#[endpoint(
  tags("maintenance")
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn get_service_info(req: &mut Request, res: &mut Response, depot: &mut Depot) -> MResult<MsgPack<GetAppAuthConfigurationResponse>> {
  let request = req.parse_msgpack::<GetAppAuthConfigurationRequest>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  
  verify_sign_by_header(req, &request, &request.author_dpub)?;
  
  let app_conf = kv.get::<AppAuthConfiguration>(&KvDb::app(&request.app_name)).await?
    .ok_or(ErrorResponse::from("There is no such app.").with_400_pub().build())?;
  if app_conf.author_dpub.as_slice().ne(request.author_dpub.as_slice()) {
    return Err(
      ErrorResponse::from("Insufficient rights to read service info. Provide author's public key which also written on service' registration.")
        .with_400_pub()
        .build()
    )
  }
  
  let answer = GetAppAuthConfigurationResponse {
    config: app_conf,
    author_dpub: request.author_dpub,
    c3a_dpub: keypair.public.to_vec(),
  };
  sign_by_header(res, &answer, &keypair)?;
  
  msgpack!(answer)
}

pub(crate) fn application_server_api() -> Router {
  Router::new()
    .push(Router::with_path("/health-check").get(health_check))
    .push(Router::with_path("/generate-invitation").post(generate_invitation))
    .push(Router::with_path("/service/register").post(service_register))
}

#[cfg(test)]
mod tests {
  use c3a_common::GenerateInvitationRequest;
use salvo::affix_state;
  use salvo::core::prelude::*;
  // use salvo::test::ResponseExt;
  use salvo::test::TestClient;
  
  async fn create_service() -> Service {
    use crate::Setup;
    
    let mut setup = Setup::default();
    setup.private_adm_key = Some("test-key-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string());
    
    let kv_db = crate::kv::KvDb::load("tests").unwrap();
    kv_db.initial_setup().await.unwrap();
    
    let router = Router::new()
      .hoop(affix_state::inject(setup).inject(kv_db))
      .push(super::application_server_api());
    
    Service::new(router)
  }
  
  #[tokio::test]
  async fn test_health_check() {
    let service = create_service().await;

    let content = TestClient::get("http://0.0.0.0:5800/health-check")
      .send(&service)
      .await;
    
    assert_eq!(content.status_code, Some(StatusCode::OK));
  }
  
  #[tokio::test]
  async fn test_health_check() {
    let service = create_service().await;

    let invite_req = GenerateInvitationRequest { private_admin_key_begin: *b"test-key-XXXXXXXXXXXXXXX" };
    
    let content = TestClient::get("http://0.0.0.0:5800/health-check")
      .send(&service)
      .await;
    
    assert_eq!(content.status_code, Some(StatusCode::OK));
  }
}
