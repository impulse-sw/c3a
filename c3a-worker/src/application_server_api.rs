//! Application server API.
//!
//! Contains methods to be called from apps' servers.
//!
//! To manage information of your app correctly and reliably, you should use the same Dilithium5 keypair every time
//! you start your application backend. You can generate keypair by `c3a_common::generate_dilithium_keypair`.
//!
//! To start, you need to register your app with invite code (request from C3A instance admin; see below)
//! (it's allowed to get `200` or `400` status codes depending on your app registration existance).

use c3a_common::{
  AppAuthConfiguration, EditAppAuthConfigurationRequest, GenerateInvitationRequest, GetAppAuthConfigurationRequest,
  GetAppAuthConfigurationResponse, RegisterAppAuthConfigurationRequest, RegisterAppAuthConfigurationResponse,
  RemoveAppRequest, generate,
};
use cc_server_kit::{prelude::*, salvo::Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
  Setup,
  kv::{KvDb, PreConverted, extract_db},
  utils::{sign_by_header, verify_sign_by_header},
};

/// Service availability check.
#[endpoint(
  tags("maintenance"),
  responses((status_code = 200, description = "Service availability check result"))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
#[allow(unused_braces)]
async fn health_check(req: &mut Request) -> MResult<OK> {
  return ok!();
}

#[derive(Deserialize, Serialize, Default)]
struct Invitations {
  invitations: HashSet<Vec<u8>>,
}

/// Generates invitation for app registration.
///
/// This method is available only for C3A administrator.
/// You should send `GenerateInvitationRequest` as MessagePack inside request body.
#[handler]
async fn generate_invitation(req: &mut Request, depot: &mut Depot) -> MResult<MsgPack<Vec<u8>>> {
  let request = req.parse_msgpack::<GenerateInvitationRequest>().await?;
  let kv = extract_db(depot)?;
  let c3a_state = depot.obtain::<Setup>()?;

  if c3a_state.private_adm_key.as_ref().unwrap().as_bytes()[..24] != request.private_admin_key_begin {
    return Err(
      ErrorResponse::from("Invalid authentication request")
        .with_401_pub()
        .build(),
    );
  }

  let mut invitations = kv.get::<Invitations>(KvDb::INVITES).await?.unwrap_or_default();
  let new_invite = generate::<1024>().to_vec();
  invitations.invitations.insert(new_invite.clone());
  kv.upsert(KvDb::INVITES, &invitations).await?;

  msgpack!(new_invite)
}

/// Register app.
///
/// To register your app, you should have application backend to send this options once on start.
/// If app is registered already, status code 400 will be returned.
#[endpoint(
  tags("maintenance"),
  request_body(
    content = RegisterAppAuthConfigurationRequest,
    content_type = "application/msgpack",
    description = "App configuration register request data"
  ),
  parameters((
    "C3A-Sign" = String,
    Header,
    description = "Dilithium5 request signature"
  )),
  responses((
    status_code = 200,
    description = "Response with C3A public Dilithium5 key",
    body = RegisterAppAuthConfigurationResponse,
    content_type = ["application/msgpack"],
    headers(("C3A-Sign" = String, description = "Dilithium5 response signature"))
  ))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn app_register(
  req: &mut Request,
  res: &mut Response,
  depot: &mut Depot,
) -> MResult<MsgPack<RegisterAppAuthConfigurationResponse>> {
  let request = req.parse_msgpack::<RegisterAppAuthConfigurationRequest>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;

  verify_sign_by_header(req, &request, &request.config.author_dpub)?;

  let mut invitations = kv.get::<Invitations>(KvDb::INVITES).await?.unwrap_or_default();
  if !invitations.invitations.contains(&request.invite) {
    return Err(
      ErrorResponse::from("Your invitation code is invalid!")
        .with_401_pub()
        .build(),
    );
  }
  invitations.invitations.remove(&request.invite);
  kv.upsert(KvDb::INVITES, &invitations).await?;

  let app_conf = request.config;
  kv.insert(&KvDb::app(&app_conf.app_name), &app_conf).await?;

  let answer = RegisterAppAuthConfigurationResponse {
    author_dpub: app_conf.author_dpub,
    c3a_dpub: keypair.public.to_vec(),
  };
  sign_by_header(res, &answer, &keypair)?;

  msgpack!(answer)
}

/// Gets information about this application.
///
/// Method exists for only application servers and their authors
/// to get know if they need to change their configuration.
#[endpoint(
  tags("maintenance"),
  request_body(
    content = GetAppAuthConfigurationRequest,
    content_type = "application/msgpack",
    description = "Get app configuration request data"
  ),
  parameters((
    "C3A-Sign" = String,
    Header,
    description = "Dilithium5 request signature"
  )),
  responses((
    status_code = 200,
    description = "Application configuration",
    body = GetAppAuthConfigurationResponse,
    content_type = ["application/msgpack"],
    headers(("C3A-Sign" = String, description = "Dilithium5 response signature"))
  ))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn app_get_info(
  req: &mut Request,
  res: &mut Response,
  depot: &mut Depot,
) -> MResult<MsgPack<GetAppAuthConfigurationResponse>> {
  let request = req.parse_msgpack::<GetAppAuthConfigurationRequest>().await?;
  let kv = extract_db(depot)?;
  let keypair = kv.get_dilithium_keypair().await?;

  let app_conf = kv
    .get::<AppAuthConfiguration>(&KvDb::app(&request.app_name))
    .await?
    .ok_or(ErrorResponse::from("There is no such app.").with_404_pub().build())?;
  if app_conf.author_dpub.as_slice().ne(request.author_dpub.as_slice()) {
    return Err(
      ErrorResponse::from("Insufficient rights to read service info. Provide author's public key which also written on service' registration.")
        .with_400_pub()
        .build()
    );
  }

  verify_sign_by_header(req, &request, &request.author_dpub)?;

  let answer = GetAppAuthConfigurationResponse {
    config: app_conf,
    c3a_dpub: keypair.public.to_vec(),
  };
  sign_by_header(res, &answer, &keypair)?;

  msgpack!(answer)
}

/// Edits app configuration.
#[endpoint(tags("maintenance"))]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn edit_app_configuration(req: &mut Request, depot: &mut Depot) -> MResult<OK> {
  let request = req.parse_msgpack::<EditAppAuthConfigurationRequest>().await?;
  let kv = extract_db(depot)?;

  let mut app_conf = kv
    .get::<AppAuthConfiguration>(&KvDb::app(&request.edit_app))
    .await?
    .ok_or(ErrorResponse::from("There is no such app.").with_404_pub().build())?;

  verify_sign_by_header(req, &request, &app_conf.author_dpub)?;

  if let Some(new_app_name) = &request.app_name {
    app_conf.app_name = new_app_name.to_owned();
  }
  if let Some(new_domain) = &request.domain {
    app_conf.domain = new_domain.to_owned();
  }
  if let Some(new_tags) = &request.allowed_tags {
    app_conf.allowed_tags = new_tags.to_owned();
  }
  if let Some(new_signup_opts) = &request.allow_sign_up {
    app_conf.allow_sign_up = Some(new_signup_opts.to_owned());
  }
  if let Some(new_client_based_auth_opts) = &request.client_based_auth_opts {
    app_conf.client_based_auth_opts = Some(new_client_based_auth_opts.to_owned());
  }

  kv.batch_ops(
    vec![(
      KvDb::app(request.app_name.as_deref().unwrap_or(&request.edit_app)),
      PreConverted::new(&app_conf)?,
    )],
    vec![KvDb::app(&request.edit_app)],
  )
  .await?;

  ok!()
}

/// Removes app configuration from C3A Service.
#[endpoint(tags("maintenance"))]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn app_remove(req: &mut Request, depot: &mut Depot) -> MResult<OK> {
  let request = req.parse_msgpack::<RemoveAppRequest>().await?;
  let kv = extract_db(depot)?;

  verify_sign_by_header(req, &request, &request.author_dpub)?;

  let app_conf = kv
    .get::<AppAuthConfiguration>(&KvDb::app(&request.app_name))
    .await?
    .ok_or(ErrorResponse::from("There is no such app.").with_400_pub().build())?;
  if app_conf.author_dpub.as_slice().ne(request.author_dpub.as_slice()) {
    return Err(
      ErrorResponse::from("Insufficient rights to read service info. Provide author's public key which also written on service' registration.")
        .with_400_pub()
        .build()
    );
  }

  kv.remove(&KvDb::app(&request.app_name)).await?;
  ok!()
}

async fn register_user(req: &mut Request, res: &mut Response, depot: &mut Depot) -> MResult<MsgPack<RegisterUserResponse>> {
  
  
  unimplemented!()
}

/// Router to application servers' API.
pub(crate) fn application_server_api() -> Router {
  Router::new()
    .push(Router::with_path("/health-check").get(health_check))
    .push(Router::with_path("/apps/generate-invitation").post(generate_invitation))
    .push(Router::with_path("/apps/register").post(app_register))
    .push(
      Router::with_path("/apps/info")
        .post(app_get_info)
        .patch(edit_app_configuration),
    )
    .push(Router::with_path("/apps/remove").delete(app_remove))
}

#[cfg(test)]
mod tests {
  use c3a_common::{
    EditAppAuthConfigurationRequest, GenerateInvitationRequest, GetAppAuthConfigurationRequest,
    GetAppAuthConfigurationResponse, RegisterAppAuthConfigurationRequest, RegisterAppAuthConfigurationResponse,
    RemoveAppRequest, base64_decode, base64_encode, sign, verify,
  };
  use cc_server_kit::test_exts::ResponseExt;
  use salvo::affix_state;
  use salvo::core::prelude::*;
  use salvo::test::TestClient;

  async fn create_service(partition_name: &str) -> Service {
    use crate::Setup;

    let mut setup = Setup::default();
    setup.private_adm_key = Some("test-key-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string());

    let kv_db = crate::kv::KvDb::load(partition_name).unwrap();
    kv_db.initial_setup().await.unwrap();

    let router = Router::new()
      .hoop(affix_state::inject(setup).inject(kv_db))
      .push(super::application_server_api());

    Service::new(router)
  }

  #[tokio::test]
  async fn test_health_check() {
    let service = create_service("tests-1").await;

    let content = TestClient::get("http://0.0.0.0:5800/health-check").send(&service).await;

    assert_eq!(content.status_code, Some(StatusCode::OK));
  }

  #[tokio::test]
  async fn test_invite_register_get_and_remove() {
    let service = create_service("tests-2").await;

    let invite_req = GenerateInvitationRequest {
      private_admin_key_begin: *b"test-key-XXXXXXXXXXXXXXX",
    };

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/generate-invitation")
      .add_header("Content-Type", "application/msgpack", true)
      .bytes(rmp_serde::to_vec(&invite_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let invite = content.take_msgpack::<Vec<u8>>().await.unwrap();
    assert_eq!(invite.len(), 1024);

    let keypair = c3a_common::generate_dilithium_keypair();
    let config = c3a_common::AppAuthConfiguration {
      app_name: String::from("test-app-01"),
      domain: String::from("test-domain.example.com"),
      allowed_tags: vec![
        c3a_common::AppTag {
          role: String::from("user"),
          scope: String::from("read"),
        },
        c3a_common::AppTag {
          role: String::from("admin"),
          scope: String::from("read"),
        },
        c3a_common::AppTag {
          role: String::from("admin"),
          scope: String::from("write"),
        },
      ],
      allow_sign_up: Some(c3a_common::SignUpOpts {
        allow_sign_up: true,
        auto_assign_tags: vec![c3a_common::AppTag {
          role: String::from("user"),
          scope: String::from("read"),
        }],
        force_2fa: false,
        min_login_size: Some(8),
        max_login_size: Some(16),
      }),
      client_based_auth_opts: None,
      author_dpub: keypair.public.to_vec(),
    };

    let app_register_req = RegisterAppAuthConfigurationRequest {
      invite,
      config: config.clone(),
    };

    let signature = sign(&app_register_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/register")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_register_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let app_register_res = content
      .take_msgpack::<RegisterAppAuthConfigurationResponse>()
      .await
      .unwrap();

    let res_sign = content
      .headers()
      .get(c3a_common::SIGN_HEADER)
      .unwrap()
      .to_str()
      .unwrap();
    let res_sign = base64_decode(&res_sign).unwrap();
    assert!(verify(&app_register_res, &res_sign, &app_register_res.c3a_dpub).unwrap());

    assert_eq!(app_register_res.author_dpub.as_slice(), &keypair.public);

    let app_info_req = GetAppAuthConfigurationRequest {
      app_name: config.app_name.to_owned(),
      author_dpub: keypair.public.to_vec(),
    };

    let signature = sign(&app_info_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/info")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_info_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let app_info_res = content.take_msgpack::<GetAppAuthConfigurationResponse>().await.unwrap();

    let res_sign = content
      .headers()
      .get(c3a_common::SIGN_HEADER)
      .unwrap()
      .to_str()
      .unwrap();
    let res_sign = base64_decode(&res_sign).unwrap();
    assert_eq!(app_register_res.c3a_dpub.as_slice(), app_info_res.c3a_dpub.as_slice());
    assert!(verify(&app_info_res, &res_sign, &app_info_res.c3a_dpub).unwrap());

    assert_eq!(app_info_res.config, config);

    let app_remove_req = RemoveAppRequest {
      app_name: config.app_name.to_owned(),
      author_dpub: keypair.public.to_vec(),
    };

    let signature = sign(&app_remove_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let content = TestClient::delete("http://0.0.0.0:5800/apps/remove")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_remove_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));
  }

  #[tokio::test]
  async fn test_edit_app_info() {
    let service = create_service("tests-3").await;

    let invite_req = GenerateInvitationRequest {
      private_admin_key_begin: *b"test-key-XXXXXXXXXXXXXXX",
    };

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/generate-invitation")
      .add_header("Content-Type", "application/msgpack", true)
      .bytes(rmp_serde::to_vec(&invite_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let invite = content.take_msgpack::<Vec<u8>>().await.unwrap();
    assert_eq!(invite.len(), 1024);

    let keypair = c3a_common::generate_dilithium_keypair();
    let config = c3a_common::AppAuthConfiguration {
      app_name: String::from("test-app-01"),
      domain: String::from("test-domain.example.com"),
      allowed_tags: vec![
        c3a_common::AppTag {
          role: String::from("user"),
          scope: String::from("read"),
        },
        c3a_common::AppTag {
          role: String::from("admin"),
          scope: String::from("read"),
        },
        c3a_common::AppTag {
          role: String::from("admin"),
          scope: String::from("write"),
        },
      ],
      allow_sign_up: Some(c3a_common::SignUpOpts {
        allow_sign_up: true,
        auto_assign_tags: vec![c3a_common::AppTag {
          role: String::from("user"),
          scope: String::from("read"),
        }],
        force_2fa: false,
        min_login_size: Some(8),
        max_login_size: Some(16),
      }),
      client_based_auth_opts: None,
      author_dpub: keypair.public.to_vec(),
    };

    let app_register_req = RegisterAppAuthConfigurationRequest {
      invite,
      config: config.clone(),
    };

    let signature = sign(&app_register_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/register")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_register_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let app_register_res = content
      .take_msgpack::<RegisterAppAuthConfigurationResponse>()
      .await
      .unwrap();

    let req_sign = content
      .headers()
      .get(c3a_common::SIGN_HEADER)
      .unwrap()
      .to_str()
      .unwrap();
    let req_sign = base64_decode(&req_sign).unwrap();
    assert!(verify(&app_register_res, &req_sign, &app_register_res.c3a_dpub).unwrap());

    assert_eq!(app_register_res.author_dpub.as_slice(), &keypair.public);

    let edit_info_req = EditAppAuthConfigurationRequest {
      edit_app: config.app_name.to_owned(),
      app_name: Some(String::from("test-app-02")),
      ..Default::default()
    };

    let signature = sign(&edit_info_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let content = TestClient::patch("http://0.0.0.0:5800/apps/info")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&edit_info_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let app_info_req = GetAppAuthConfigurationRequest {
      app_name: String::from("test-app-02"),
      author_dpub: keypair.public.to_vec(),
    };

    let signature = sign(&app_info_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let mut content = TestClient::post("http://0.0.0.0:5800/apps/info")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_info_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::OK));

    let app_info_res = content.take_msgpack::<GetAppAuthConfigurationResponse>().await.unwrap();

    let res_sign = content
      .headers()
      .get(c3a_common::SIGN_HEADER)
      .unwrap()
      .to_str()
      .unwrap();
    let res_sign = base64_decode(&res_sign).unwrap();
    assert_eq!(app_register_res.c3a_dpub.as_slice(), app_info_res.c3a_dpub.as_slice());
    assert!(verify(&app_info_res, &res_sign, &app_info_res.c3a_dpub).unwrap());

    assert!(app_info_res.config.app_name.as_str().eq("test-app-02"));
    assert!(app_info_res.config.domain.as_str().eq(config.domain.as_str()));
    assert!(app_info_res.config.allowed_tags.eq(&config.allowed_tags));

    let app_info_req = GetAppAuthConfigurationRequest {
      app_name: String::from("test-app-01"),
      author_dpub: keypair.public.to_vec(),
    };

    let signature = sign(&app_info_req, &keypair).unwrap();
    let signature = base64_encode(&signature);

    let content = TestClient::post("http://0.0.0.0:5800/apps/info")
      .add_header("Content-Type", "application/msgpack", true)
      .add_header(c3a_common::SIGN_HEADER, signature.as_str(), true)
      .bytes(rmp_serde::to_vec(&app_info_req).unwrap())
      .send(&service)
      .await;

    assert_eq!(content.status_code, Some(StatusCode::NOT_FOUND));
  }
}
