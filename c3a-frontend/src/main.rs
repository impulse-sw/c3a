mod info;
mod sign_in;
mod sign_up;

use cc_ui_kit::prelude::*;
use cc_ui_kit::router::{get_path, redirect};
use leptos_meta::*;

leptos_i18n::load_locales!();
use crate::i18n::*;
use crate::info::InfoPage;
use crate::sign_in::SignInPage;
use crate::sign_up::SignUpPage;

fn main() {
  setup_app(
    log::Level::Info,
    Box::new(move || {
      view! {
        <I18nContextProvider>
          <App />
        </I18nContextProvider>
      }
      .into_any()
    }),
  )
}

#[component]
fn App() -> impl IntoView {
  provide_meta_context();
  let i18n = use_i18n();

  view! {
    <Title
      text=move || t_string!(i18n, title)
      formatter=move |text| format!("{text} - CC Services")
    />
    {move || match get_path().unwrap().as_str() {
      "/sign-up" => view! { <SignUpPage /> }.into_any(),
      "/sign-in" => view! { <SignInPage /> }.into_any(),
      "/" => view! { <InfoPage /> }.into_any(),
      _ => {
        redirect("/404".to_string()).unwrap();
        view! {}.into_any()
      }
    }}
  }
}
