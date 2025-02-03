mod auth;
mod services;

use cc_server_kit::prelude::*;
// use cc_server_kit::cc_utils::prelude::*;
use cc_static_server::frontend_router;
use salvo::affix_state;

static KV_ADDR: &str = "redis://valkey:6379";

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

#[derive(Default, Clone)]
struct Setup {
  generic_values: GenericValues,
}

impl GenericSetup for Setup {
  fn generic_values(&self) -> &GenericValues { &self.generic_values }
  fn set_generic_values(&mut self, generic_values: GenericValues) { self.generic_values = generic_values; }
}

#[tokio::main]
async fn main() {
  let setup = load_generic_config::<Setup>("c3a-worker").await.unwrap();
  let state = load_generic_state(&setup).await.unwrap();
  let kv_db = connect_redis(KV_ADDR).await.unwrap();
  let router = get_root_router(&state)
    .hoop(affix_state::inject(state.clone()).inject(setup.clone()).inject(kv_db))
    .push(frontend_router());
  let (server, _) = start(state, &setup, router).await.unwrap();
  server.await
}
