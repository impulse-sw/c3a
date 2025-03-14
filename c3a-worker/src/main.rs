#![feature(let_chains, string_from_utf8_lossy_owned)]
#![deny(warnings)]

use cc_server_kit::prelude::*;
use cc_static_server::frontend_router;
use salvo::affix_state;
use serde::Deserialize;

mod api;
mod services;

pub(crate) mod core;
pub(crate) mod kv;
pub(crate) mod mailer;
pub(crate) mod utils;

use crate::api::applications::application_server_api;

#[derive(Deserialize, Default, Clone)]
pub(crate) struct Setup {
  #[serde(flatten)]
  generic_values: GenericValues,
  private_adm_key: Option<String>,
}

impl GenericSetup for Setup {
  fn generic_values(&self) -> &GenericValues {
    &self.generic_values
  }
  fn generic_values_mut(&mut self) -> &mut GenericValues {
    &mut self.generic_values
  }
}

#[tokio::main]
async fn main() -> MResult<()> {
  let mut setup = load_generic_config::<Setup>("c3a-worker").await.unwrap();
  if setup.private_adm_key.is_some() {
    panic!("You can't setup private key in `c3a-worker.yaml`!")
  }

  dotenv::dotenv().ok();
  setup.private_adm_key = Some(
    if let Ok(key) = std::env::var("C3A_PRIVATE_ADM_KEY")
      && key.chars().count() >= 128
    {
      key
    } else {
      return Err(ErrorResponse::from(
        "There is no `C3A_PRIVATE_ADM_KEY` env variable with key of at least 128 chars!",
      ));
    },
  );

  let state = load_generic_state(&setup).await?;

  let kv_db = crate::kv::KvDb::load("data")?;
  kv_db.initial_setup().await?;

  let mailer = crate::mailer::init_mailer()?;

  let router = get_root_router(&state)
    .hoop(
      affix_state::inject(state.clone())
        .inject(setup.clone())
        .inject(kv_db)
        .inject(mailer),
    )
    .push(frontend_router())
    .push(application_server_api());
  let (server, _) = start(state, &setup, router).await?;

  server.await;
  Ok(())
}
