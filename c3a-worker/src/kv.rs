use c3a_common::AppAuthConfiguration;
use cc_server_kit::prelude::*;
use fjall::{Keyspace, PartitionHandle, PersistMode, Slice};
use serde::{Serialize, de::DeserializeOwned};
use sha3::{Digest, Sha3_256};

#[derive(Clone)]
pub(crate) struct KvDb {
  keyspace: Keyspace,
  db: PartitionHandle,
}

pub(crate) struct PreConverted {
  val: Vec<u8>,
}

impl PreConverted {
  pub(crate) fn new<T: Serialize>(value: &T) -> MResult<Self> {
    Ok(Self {
      val: rmp_serde::to_vec(value).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?,
    })
  }

  pub(crate) fn as_ref(&self) -> &Vec<u8> {
    &self.val
  }

  pub(crate) fn from_raw(slice: Slice) -> Self {
    Self { val: slice.to_vec() }
  }

  #[allow(dead_code)]
  pub(crate) fn try_from<T: DeserializeOwned>(&self) -> MResult<T> {
    rmp_serde::from_slice::<T>(&self.val).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())
  }
}

#[allow(dead_code)]
impl KvDb {
  pub(crate) const MAIN_SECRET_KEY: &str = "main_secret";
  pub(crate) const MAIN_DLTH_PUB_KEY: &str = "main_sign_pub";
  pub(crate) const MAIN_DLTH_PRV_KEY: &str = "main_sign_prv";

  pub(crate) const INVITES: &str = "invites";

  pub(crate) const APPLICATION_PREFIX: &str = "app::";
  pub(crate) const USER_PREFIX: &str = "user::";

  pub(crate) fn load(partition_name: &str) -> MResult<Self> {
    let keyspace = fjall::Config::default()
      .open()
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500_pub().build())?;
    let db = keyspace
      .open_partition(partition_name, Default::default())
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500_pub().build())?;

    Ok(Self { keyspace, db })
  }

  pub(crate) async fn initial_setup(&self) -> MResult<()> {
    if self.get::<Vec<u8>>(KvDb::MAIN_SECRET_KEY).await?.is_none() {
      tracing::info!("There is no main secret key, generating...");
      let new_secret = c3a_common::generate_chacha20poly1305_key();
      self.insert(KvDb::MAIN_SECRET_KEY, &new_secret.to_vec()).await?;
      tracing::info!("Main secret key is generated.");
    }

    if self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PUB_KEY).await?.is_none()
      || self.get::<Vec<u8>>(KvDb::MAIN_DLTH_PRV_KEY).await?.is_none()
    {
      tracing::info!("There is no sign keypair, generating...");
      let keypair = c3a_common::generate_dilithium_keypair();
      self.insert(KvDb::MAIN_DLTH_PUB_KEY, &keypair.public.to_vec()).await?;
      self
        .insert(KvDb::MAIN_DLTH_PRV_KEY, &keypair.expose_secret().to_vec())
        .await?;
      tracing::info!("Sign keypair generated.");
    }

    Ok(())
  }

  pub(crate) fn app(app_name: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(app_name.as_bytes());
    let hash = hex::encode(hasher.finalize());

    format!("{}{}", Self::APPLICATION_PREFIX, hash)
  }

  pub(crate) fn user(user_name: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(user_name.as_bytes());
    let hash = hex::encode(hasher.finalize());

    format!("{}{}", Self::USER_PREFIX, hash)
  }

  pub(crate) async fn exists(&self, key: &str) -> MResult<bool> {
    let state = self.clone();
    let _key = key.to_string();

    let exists = tokio::task::spawn_blocking(move || state.db.contains_key(_key))
      .await
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

    Ok(exists)
  }

  pub(crate) async fn get_dilithium_keypair(&self) -> MResult<c3a_common::Keypair> {
    let pub_key = self
      .get::<Vec<u8>>(KvDb::MAIN_DLTH_PUB_KEY)
      .await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    let prv_key = self
      .get::<Vec<u8>>(KvDb::MAIN_DLTH_PRV_KEY)
      .await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    c3a_common::Keypair::restore(&pub_key, &prv_key)
      .map_err(|_| ErrorResponse::from("Can't restore keypair!").with_500().build())
  }

  pub(crate) async fn get_secret_key(&self) -> MResult<[u8; 256]> {
    use std::mem::MaybeUninit;

    let secret = self
      .get::<Vec<u8>>(KvDb::MAIN_SECRET_KEY)
      .await?
      .ok_or(ErrorResponse::from("No public key available!").with_500().build())?;
    let buffer: [MaybeUninit<u8>; 256] = unsafe { MaybeUninit::uninit().assume_init() };
    let mut buffer = unsafe { std::mem::transmute::<[MaybeUninit<u8>; 256], [u8; 256]>(buffer) };
    buffer.copy_from_slice(&secret);
    Ok(buffer)
  }

  pub(crate) async fn get_app_conf(&self, app_name: &str) -> MResult<AppAuthConfiguration> {
    self
      .get::<AppAuthConfiguration>(&KvDb::app(app_name))
      .await?
      .ok_or(ErrorResponse::from("There is no such app.").with_404_pub().build())
  }

  pub(crate) async fn get<T: DeserializeOwned>(&self, key: &str) -> MResult<Option<T>> {
    let state = self.clone();
    let _key = key.to_string();

    let item = tokio::task::spawn_blocking(move || state.db.get(&_key))
      .await
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

    let slice = if let Some(item) = item { item } else { return Ok(None) };
    let value =
      rmp_serde::from_slice::<T>(&slice).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

    tracing::trace!("fjall: got value by path `{}`", key);

    Ok(Some(value))
  }

  pub(crate) async fn insert<T: Serialize>(&self, key: &str, value: &T) -> MResult<()> {
    let vec = rmp_serde::to_vec(value).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
    let state = self.clone();
    let _key = key.to_string();

    tokio::task::spawn_blocking(move || {
      if state
        .db
        .contains_key(&_key)
        .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
      {
        return Err(ErrorResponse::from("Key already exists!").with_400().build());
      }
      state
        .db
        .insert(&_key, vec)
        .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;
      state
        .keyspace
        .persist(PersistMode::SyncAll)
        .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())??;

    tracing::trace!("fjall: inserted value by path `{}`", key);

    Ok(())
  }

  pub(crate) async fn upsert<T: Serialize>(&self, key: &str, value: &T) -> MResult<()> {
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

    tracing::trace!("fjall: upserted value by path `{}`", key);

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
    let value =
      rmp_serde::from_slice::<T>(&slice).map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

    tracing::trace!("fjall: popped value by path `{}`", key);

    Ok(Some(value))
  }

  pub(crate) async fn batch_ops(
    &self,
    get: Vec<String>,
    upsert: Vec<(String, PreConverted)>,
    remove: Vec<String>,
  ) -> MResult<Vec<(String, Option<PreConverted>)>> {
    let state = self.clone();

    let values = tokio::task::spawn_blocking(move || {
      let mut values = vec![];

      for key in get {
        values.push((key.to_owned(), state.db.get(&key)?.map(PreConverted::from_raw)));
      }

      let mut batch = state.keyspace.batch();

      for key in remove {
        batch.remove(&state.db, key.clone());
      }
      for (key, value) in upsert {
        batch.insert(&state.db, key.clone(), value.as_ref());
      }

      batch.commit()?;
      state.keyspace.persist(PersistMode::SyncAll)?;

      fjall::Result::<Vec<(String, Option<PreConverted>)>>::Ok(values)
    })
    .await
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
    .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?;

    Ok(values)
  }
}

pub(crate) fn extract_db(depot: &mut Depot) -> MResult<KvDb> {
  Ok(
    depot
      .obtain::<KvDb>()
      .map_err(|_| ErrorResponse::from("Can't get `KvDb` instance").with_500().build())?
      .clone(),
  )
}
