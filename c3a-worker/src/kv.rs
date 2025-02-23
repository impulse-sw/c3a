use cc_server_kit::prelude::*;
use fjall::{Keyspace, PartitionHandle, PersistMode};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone)]
pub(crate) struct KvDb {
  keyspace: Keyspace,
  db: PartitionHandle,
}

#[allow(dead_code)]
pub(crate) struct PreConverted {
  val: Vec<u8>,
}

#[allow(dead_code)]
impl PreConverted {
  pub(crate) fn new<T: Serialize>(value: &T) -> MResult<Self> {
    Ok(Self { val: rmp_serde::to_vec(value).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())? })
  }
  
  pub(crate) fn as_ref(&self) -> &Vec<u8> { &self.val }
}

#[allow(dead_code)]
impl KvDb {
  pub(crate) const MAIN_SECRET_KEY: &str = "main_secret";
  pub(crate) const MAIN_DLTH_PUB_KEY: &str = "main_sign_pub";
  pub(crate) const MAIN_DLTH_PRV_KEY: &str = "main_sign_prv";
  
  pub(crate) const INVITES: &str = "invites";
  
  pub(crate) const APPLICATION_PREFIX: &str = "app::{app_name}";
  pub(crate) const USER_PREFIX: &str = "user::{user_name}";
  
  pub(crate) fn load(partition_name: &str) -> MResult<Self> {
    let keyspace = fjall::Config::default().open().map_err(|e| ErrorResponse::from(e.to_string()).with_500_pub().build())?;
    let db = keyspace.open_partition(partition_name, Default::default()).map_err(|e| ErrorResponse::from(e.to_string()).with_500_pub().build())?;
    
    Ok(Self { keyspace, db })
  }
  
  pub(crate) async fn initial_setup(&self) -> MResult<()> {
    if self.get::<Vec<u8>>(KvDb::MAIN_SECRET_KEY).await?.is_none() {
      tracing::info!("There is no main secret key, generating...");
      let new_secret = c3a_common::generate_chacha20poly1305_key();
      self.insert(KvDb::MAIN_SECRET_KEY, &new_secret.to_vec()).await?;
      tracing::info!("Main secret key is generated.");
    }
    
    if self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PUB_KEY).await?.is_none() || self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PRV_KEY).await?.is_none() {
      tracing::info!("There is no sign keypair, generating...");
      let keypair = c3a_common::generate_dilithium_keypair();
      self.insert(KvDb::MAIN_DLTH_PUB_KEY, &keypair.public.to_vec()).await?;
      self.insert(KvDb::MAIN_DLTH_PRV_KEY, &keypair.expose_secret().to_vec()).await?;
      tracing::info!("Sign keypair generated.");
    }
    
    Ok(())
  }
  
  pub(crate) async fn get_dilithium_keypair(&self) -> MResult<c3a_common::Keypair> {
    let pub_key = self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PUB_KEY).await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    let prv_key = self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PRV_KEY).await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    c3a_common::Keypair::restore(&pub_key, &prv_key).map_err(|_| ErrorResponse::from("Can't restore keypair!").with_500().build())
  }
  
  pub(crate) async fn get_secret_key(&self) -> MResult<[u8; 256]> {
    use std::mem::MaybeUninit;
    
    let secret = self.get::<Vec<u8>>(KvDb::MAIN_SECRET_KEY).await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    let buffer: [MaybeUninit<u8>; 256] = unsafe { MaybeUninit::uninit().assume_init() };
    let mut buffer = unsafe { std::mem::transmute::<[MaybeUninit<u8>; 256], [u8; 256]>(buffer) };
    buffer.copy_from_slice(&secret);
    Ok(buffer)
  }
  
  pub(crate) async fn get<T: DeserializeOwned>(&self, key: &str) -> MResult<Option<T>> {
    let state = self.clone();
    let _key = key.to_string();
    
    let item = tokio::task::spawn_blocking(move || state.db.get(&_key))
      .await
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    let slice = if let Some(item) = item { item } else { return Ok(None) };
    let value = rmp_serde::from_slice::<T>(&slice).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    tracing::trace!("fjall: got value by path `{}`", key);
    
    Ok(Some(value))
  }
  
  pub(crate) async fn insert<T: Serialize>(&self, key: &str, value: &T) -> MResult<()> {
    let vec = rmp_serde::to_vec(value).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    let state = self.clone();
    let _key = key.to_string();
    
    tokio::task::spawn_blocking(move || {
      state.db.insert(&_key, vec)?;
      state.keyspace.persist(PersistMode::SyncAll)
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    tracing::trace!("fjall: inserted value by path `{}`", key);
    
    Ok(())
  }
  
  pub(crate) async fn remove(&self, key: &str) -> MResult<()> {
    let state = self.clone();
    let _key = key.to_string();
    
    tokio::task::spawn_blocking(move || {
      state.db.remove(&_key)?;
      state.keyspace.persist(PersistMode::SyncAll)
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    tracing::trace!("fjall: removed value by path `{}`", key);
    
    Ok(())
  }
  
  pub(crate) async fn pop<T: DeserializeOwned>(&self, key: &str) -> MResult<Option<T>> {
    let state = self.clone();
    let _key = key.to_string();
    
    let item = tokio::task::spawn_blocking(move || {
      let item = state.db.get(&_key).map(|o| o.map(|s| s.to_vec()))?;
      if item.is_some() {
        state.db.remove(&_key)?;
        state.keyspace.persist(PersistMode::SyncAll)?;
      }
      fjall::Result::Ok(item)
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    let slice = if let Some(item) = item { item } else { return Ok(None) };
    let value = rmp_serde::from_slice::<T>(&slice).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    tracing::trace!("fjall: popped value by path `{}`", key);
    
    Ok(Some(value))
  }
  
  pub(crate) async fn batch_ops(&self, insert: Vec<(String, PreConverted)>, remove: Vec<String>) -> MResult<()> {
    let state = self.clone();
    
    tokio::task::spawn_blocking(move || {
      let mut batch = state.keyspace.batch();

      for key in remove { batch.remove(&state.db, key.clone()); }
      for (key, value) in insert { batch.insert(&state.db, key.clone(), value.as_ref()); }

      batch.commit()?;
      state.keyspace.persist(PersistMode::SyncAll)
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    
    Ok(())
  }
}

pub(crate) fn extract_db(depot: &mut Depot) -> MResult<KvDb> {
  Ok(
    depot.obtain::<KvDb>()
      .map_err(|_| ErrorResponse::from("Can't get `KvDb` instance").with_500().build())?
      .clone()
  )
}
