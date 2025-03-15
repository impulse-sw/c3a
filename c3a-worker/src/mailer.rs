use cc_server_kit::prelude::*;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};

pub(crate) fn extract_mailer(depot: &mut Depot) -> MResult<AsyncSmtpTransport<Tokio1Executor>> {
  Ok(
    depot
      .obtain::<AsyncSmtpTransport<Tokio1Executor>>()
      .map_err(|_| {
        ErrorResponse::from("Can't get `AsyncSmtpTransport<Tokio1Executor>` instance")
          .with_500()
          .build()
      })?
      .clone(),
  )
}

pub(crate) fn init_mailer() -> MResult<AsyncSmtpTransport<Tokio1Executor>> {
  let creds = Credentials::new(std::env::var("SMTP_USERNAME")?, std::env::var("SMTP_PASSWORD")?);
  let mailer: AsyncSmtpTransport<Tokio1Executor> =
    AsyncSmtpTransport::<Tokio1Executor>::relay(std::env::var("SMTP_ADDR")?.as_str())
      .map_err(|e| ErrorResponse::from(e.to_string()).with_500().build())?
      .credentials(creds)
      .build();

  Ok(mailer)
}
