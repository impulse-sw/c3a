use cc_ui_kit::prelude::*;
use leptos_meta::Title;

use crate::i18n::*;
use crate::components::Centered;

#[component]
pub(crate) fn InfoPage() -> impl IntoView {
  let i18n = use_i18n();
  
  view! {
    <Title text=move || t_string!(i18n, title) />
    <Centered>
      <p>"Hello world!"</p>
    </Centered>
  }
}
