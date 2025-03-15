use cc_server_kit::prelude::*;
use passwords::PasswordGenerator;

pub(crate) fn generate_numeric(length: usize) -> MResult<String> {
  let pg = PasswordGenerator {
    length,
    numbers: true,
    lowercase_letters: false,
    uppercase_letters: false,
    symbols: true,
    spaces: false,
    exclude_similar_characters: false,
    strict: true,
  };

  pg.generate_one().map_err(|e| ErrorResponse::from(e).with_500().build())
}
