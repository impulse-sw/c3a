use cc_server_kit::prelude::*;
use cc_static_server::frontend_router;
use serde::Deserialize;
use salvo::affix_state;

mod application_server_api;
mod services;

pub(crate) type TokensDbPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

async fn connect_redis(redis_url: &str) -> MResult<TokensDbPool> {
  use bb8_redis::RedisConnectionManager;
  use bb8::Pool as Bb8Pool;
  
  let manager = RedisConnectionManager::new(redis_url)
    .map_err(|_| format!("Не удалось подключиться к базе данных (`{}`) через bb8_redis.", redis_url))?;
  Ok(
    Bb8Pool::builder()
      .build(manager)
      .await
      .map_err(|_| "Не удалось построить пул соединений через bb8_redis, хотя подключение прошло успешно.".to_string())?
  )
}

#[derive(Deserialize, Default, Clone)]
struct Setup {
  #[serde(flatten)]
  generic_values: GenericValues,
  kv_addr: String,
  seaorm_addr: String,
  private_adm_key: Option<String>,
}

impl GenericSetup for Setup {
  fn generic_values(&self) -> &GenericValues { &self.generic_values }
  fn generic_values_mut(&mut self) -> &mut GenericValues { &mut self.generic_values }
}

#[tokio::main]
async fn main() -> MResult<()> {
  let mut setup = load_generic_config::<Setup>("c3a-worker").await.unwrap();
  if setup.private_adm_key.is_some() { panic!("You can't setup private key in `c3a-worker.yaml`!") }
  setup.private_adm_key = Some(std::env::var("C3A_PRIVATE_ADM_KEY")?);
  
  let state = load_generic_state(&setup).await.unwrap();
  let kv_db = connect_redis(&setup.kv_addr).await.unwrap();
  let router = get_root_router(&state)
    .hoop(affix_state::inject(state.clone()).inject(setup.clone()).inject(kv_db))
    .push(frontend_router());
  let (server, _) = start(state, &setup, router).await.unwrap();
  
  server.await;
  Ok(())
}
