use cc_server_kit::prelude::*;
use cc_static_server::frontend_router;
use serde::Deserialize;
use salvo::affix_state;

mod auth;
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
}

impl GenericSetup for Setup {
  fn generic_values(&self) -> &GenericValues { &self.generic_values }
  fn generic_values_mut(&mut self) -> &mut GenericValues { &mut self.generic_values }
}

#[tokio::main]
async fn main() {
  let keys = pqc_dilithium::Keypair::generate();
  println!("keys.public.len() = {}", keys.public.len());
  println!("keys.expose_secret().len() = {}", keys.expose_secret().len());
  
  let setup = load_generic_config::<Setup>("c3a-worker").await.unwrap();
  let state = load_generic_state(&setup).await.unwrap();
  let kv_db = connect_redis(&setup.kv_addr).await.unwrap();
  let router = get_root_router(&state)
    .hoop(affix_state::inject(state.clone()).inject(setup.clone()).inject(kv_db))
    .push(frontend_router());
  let (server, _) = start(state, &setup, router).await.unwrap();
  
  server.await
}
