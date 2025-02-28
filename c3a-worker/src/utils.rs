use c3a_common::{base64_decode, base64_encode, sign, verify};
use cc_server_kit::prelude::*;
use cc_server_kit::salvo::{Request, Response};

pub(crate) fn verify_sign_by_header(req: &mut Request, value: &impl serde::Serialize, public: &[u8]) -> MResult<()> {
  let req_sign = req.header::<String>(c3a_common::SIGN_HEADER).ok_or(
    ErrorResponse::from("There is no sign in `C3A-Sign` header provided.")
      .with_401_pub()
      .build(),
  )?;
  let req_sign = base64_decode(&req_sign).map_err(|e| {
    ErrorResponse::from(format!("Decode from base64 error: {e:?}"))
      .with_401()
      .build()
  })?;

  if !verify(&value, &req_sign, public)
    .map_err(|e| ErrorResponse::from(format!("Verify error: {e:?}")).with_401().build())?
  {
    return Err(ErrorResponse::from("Signature is invalid.").with_401_pub().build());
  }

  Ok(())
}

pub(crate) fn sign_by_header(
  res: &mut Response,
  value: &impl serde::Serialize,
  keypair: &c3a_common::Keypair,
) -> MResult<()> {
  let sign = sign(&value, keypair).map_err(|e| ErrorResponse::from(format!("Sign error: {e:?}")).with_500().build())?;
  let sign = base64_encode(&sign);
  res.add_header(c3a_common::SIGN_HEADER, sign, true).map_err(|e| {
    ErrorResponse::from(format!("Add header error: {e:?}"))
      .with_500()
      .build()
  })?;

  Ok(())
}
