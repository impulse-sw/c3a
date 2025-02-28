use cc_ui_kit::prelude::*;

#[component]
pub(crate) fn Centered(children: Children) -> impl IntoView {
  view! { <div class="flex flex-col items-center justify-center min-h-screen">{children()}</div> }
}
