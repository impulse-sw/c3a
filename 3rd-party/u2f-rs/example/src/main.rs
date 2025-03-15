#![feature(proc_macro_hygiene, decl_macro)]

use std::io;

use rocket::http::CookieJar;
use u2f::messages::*;
use u2f::protocol::*;
use u2f::register::*;

use rocket::fs::NamedFile;
use rocket::http::Cookie;
use rocket::response::status::NotFound;
use rocket::serde::json::Json;
use rocket::{State, catch, catchers, get, post, routes};

use serde_json::{Value as JsonValue, json};
use std::sync::Mutex;

static APP_ID: &'static str = "https://localhost:30443";

lazy_static::lazy_static! {
    // In a real application this could be a database lookup.
    static ref REGISTRATIONS: Mutex<Vec<Registration>> = {
        let registrations: Mutex<Vec<Registration>> = Mutex::new(vec![]);
        registrations
    };
}

struct U2fClient {
  pub u2f: U2f,
}

#[get("/")]
async fn index() -> io::Result<NamedFile> {
  NamedFile::open("static/index.html").await
}

#[get("/api/register_request", format = "application/json")]
fn register_request(cookies: &CookieJar, state: &State<U2fClient>) -> Json<U2fRegisterRequest> {
  let challenge = state.u2f.generate_challenge();
  let challenge_str = serde_json::to_string(&challenge);

  // Only for this demo we will keep the challenge in a private (encrypted) cookie
  cookies.add_private(Cookie::new("challenge", challenge_str.unwrap()));

  // Send registration request to the browser.
  let u2f_request = state
    .u2f
    .request(challenge.clone(), REGISTRATIONS.lock().unwrap().clone());

  Json(u2f_request.unwrap())
}

#[post("/api/register_response", format = "application/json", data = "<response>")]
fn register_response(
  cookies: &CookieJar,
  response: Json<RegisterResponse>,
  state: &State<U2fClient>,
) -> Result<JsonValue, NotFound<String>> {
  let cookie = cookies.get_private("challenge");

  if let Some(ref cookie) = cookie {
    let challenge: Challenge = serde_json::from_str(cookie.value()).unwrap();
    let registration = state.u2f.register_response(challenge, response.into_inner());
    match registration {
      Ok(reg) => {
        REGISTRATIONS.lock().unwrap().push(reg);
        cookies.remove(Cookie::build("challenge"));
        return Ok(json!({"status": "success"}));
      }
      Err(e) => {
        return Err(NotFound(format!("{:?}", e.to_string())));
      }
    }
  } else {
    return Err(NotFound(format!("Not able to recover challenge")));
  }
}

#[get("/api/sign_request", format = "application/json")]
fn sign_request(cookies: &CookieJar, state: &State<U2fClient>) -> Json<U2fSignRequest> {
  let challenge = state.u2f.generate_challenge();
  let challenge_str = serde_json::to_string(&challenge);

  // Only for this demo we will keep the challenge in a private (encrypted) cookie
  cookies.add_private(Cookie::new("challenge", challenge_str.unwrap()));

  let signed_request = state.u2f.sign_request(challenge, REGISTRATIONS.lock().unwrap().clone());

  return Json(signed_request);
}

#[post("/api/sign_response", format = "application/json", data = "<response>")]
fn sign_response(
  cookies: &CookieJar,
  response: Json<SignResponse>,
  state: &State<U2fClient>,
) -> Result<JsonValue, NotFound<String>> {
  let cookie = cookies.get_private("challenge");
  if let Some(ref cookie) = cookie {
    let challenge: Challenge = serde_json::from_str(cookie.value()).unwrap();

    let registrations = REGISTRATIONS.lock().unwrap().clone();
    let sign_resp = response.into_inner();

    let mut _counter: u32 = 0;
    for registration in registrations {
      let response = state
        .u2f
        .sign_response(challenge.clone(), registration, sign_resp.clone(), _counter);
      match response {
        Ok(new_counter) => {
          _counter = new_counter;
          return Ok(json!({"status": "success"}));
        }
        Err(_e) => {
          break;
        }
      }
    }
    return Err(NotFound(format!("error verifying response")));
  } else {
    return Err(NotFound(format!("Not able to recover challenge")));
  }
}

#[catch(404)]
fn not_found() -> JsonValue {
  json!({
      "status": "error",
      "reason": "Resource was not found."
  })
}

#[rocket::launch]
fn rocket() -> _ {
  let u2f_client = U2fClient {
    u2f: U2f::new(APP_ID.into()),
  };

  rocket::build()
    .mount(
      "/",
      routes![index, register_request, register_response, sign_request, sign_response],
    )
    .register("/", catchers![not_found])
    .manage(u2f_client)
}
