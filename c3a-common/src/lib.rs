#![deny(warnings, clippy::todo, clippy::unimplemented)]

mod types;
pub use types::*;

mod utils;
pub use utils::*;

#[cfg(feature = "pqc-utils")]
pub use pqc_dilithium::Keypair;

pub const SIGN_HEADER: &str = "C3A-Sign";
pub const PREREGISTER_HEADER: &str = "C3A-Registration-State";
pub const ACCESS_TOKEN: &str = "C3A-Access";
pub const REFRESH_TOKEN: &str = "C3A-Refresh";

pub use chrono;
