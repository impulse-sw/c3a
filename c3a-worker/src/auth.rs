use cc_server_kit::prelude::*;

/// Service availability check.
#[endpoint(
  tags("maintenance"),
  responses((status_code = 200, description = "Service availability check result"))
)]
#[instrument(skip_all, fields(http.uri = req.uri().path(), http.method = req.method().as_str()))]
async fn health_check(req: &mut Request) -> MResult<OK> { ok!() }



/// Register service.
/// 
/// To register your service, you should have service backend to send this options once on start.
/// If service is registered already, and you've provided 
#[endpoint]
async fn service_register(req: &mut Request, depot: &mut Depot) -> MResult<MsgPack<>> {
  let app_conf = req.parse_msgpack::<AppAuthConfiguration>()
  msgpack!()
}

pub 
