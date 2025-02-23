use c3a_common::{generate, AppAuthConfiguration, GenerateInvitationRequest, RegisteredAnswer};
use cc_server_kit::{prelude::*, salvo::Response};
use serde::{Deserialize, Serialize};

use crate::{kv::{extract_db, KvDb}, utils::{sign_by_header, verify_sign_by_header}, Setup};

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
  invitations: Vec<Vec<u8>>,
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
  invitations.invitations.push(new_invite.clone());
  kv.insert(KvDb::INVITES, &invitations).await?;
  
  msgpack!(new_invite)
}

/// Register service.
/// 
/// To register your service, you should have service backend to send this options once on start.
#[endpoint(
  tags("maintenance"),
  responses((status_code = 200, description = "Service availability check result", body = RegisteredAnswer, content_type = ["application/msgpack"]))
)]
async fn service_register(req: &mut Request, res: &mut Response, depot: &mut Depot) -> MResult<MsgPack<RegisteredAnswer>> {
  let app_conf = req.parse_msgpack::<AppAuthConfiguration>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;
  
  verify_sign_by_header(req, &app_conf, &app_conf.author_dpub)?;
  
  // todo!("Не реализована часть регистрации сервиса!");
  
  let answer = RegisteredAnswer { author_dpub: app_conf.author_dpub, c3a_dpub: keypair.public.to_vec() };
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
  use salvo::core::prelude::*;
  // use salvo::test::ResponseExt;
  use salvo::test::TestClient;
  
  #[tokio::test]
  async fn test_health_check() {
    let service = Service::new(super::application_server_api());

    let content = TestClient::get("http://0.0.0.0:5800/health-check")
      .send(&service)
      .await;
    
    assert_eq!(content.status_code, Some(StatusCode::OK));
  }
}
