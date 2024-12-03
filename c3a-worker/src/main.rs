use cc_server_kit::prelude::*;
use cc_server_kit::utils::prelude::*;

#[derive(Default, Clone)]
struct Setup {
  generic_values: GenericValues,
}

impl GenericSetup for Setup {
  fn generic_values(&self) -> &GenericValues { &self.generic_values }
  fn set_generic_values(&mut self, generic_values: GenericValues) { self.generic_values = generic_values; }
}

const LOCAL_FRONTEND_DISTRIBUTABLE: &str = "c3a-frontend/";
const CONTAINER_FRONTEND_DISTRIBUTABLE: &str = "/usr/local/frontend-dist/";

async fn get_filepath_from_dist(filename: impl Into<String>) -> MResult<String> {
  let filename = filename.into();
  tracing::debug!("Пытаемся получить доступ к файлу {}", filename);
  
  let filepath = format!("{}{}", CONTAINER_FRONTEND_DISTRIBUTABLE, &filename);
  if tokio::fs::try_exists(&filepath).await? { return Ok(filepath) }
  let filepath = format!("{}{}", LOCAL_FRONTEND_DISTRIBUTABLE, &filename);
  if tokio::fs::try_exists(&filepath).await? { return Ok(filepath) }
    
  Err(ErrorResponse::from(format!(r#"Не удалось открыть файл "{}""#, filename)).with_404_pub().build())
}

async fn get_from_dist(filename: impl Into<String>) -> MResult<File> {
  let filename = filename.into();
  let filepath = get_filepath_from_dist(&filename).await?;
  file_upload!(filepath, filename)
}

#[handler]
#[tracing::instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn frontend(req: &Request) -> MResult<Html> {
  let filepath = get_filepath_from_dist("index.html").await?;
  let site = tokio::fs::read_to_string(&filepath).await?;
  html!(site)
}

#[handler]
#[tracing::instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn get_uikit_app_internals(req: &Request) -> MResult<File> {
  let rest_path = req.param::<String>("rest_path").ok_or("Не удалось получить остальной путь.")?;
  get_from_dist(rest_path).await.consider(Some(StatusCode::NOT_FOUND), None::<String>, true)
}

fn frontend_router() -> Router {
  Router::new()
    .get(frontend)
    .push(Router::with_path("sign-in").get(frontend))
    .push(Router::with_path("sign-up").get(frontend))
    .push(Router::with_path("<**rest_path>").get(get_uikit_app_internals))
}

#[tokio::main]
async fn main() {
  let setup = load_generic_config::<Setup>("c3a-worker").await.unwrap();
  let state = load_generic_state(&setup).await.unwrap();
  let router = get_root_router(&state, setup.clone()).push(frontend_router());
  let (server, _) = start(state, &setup, router).await.unwrap();
  server.await
}
