use cc_ui_kit::prelude::*;
use cc_ui_kit::router::get_path;
use log::info;

fn main() {
  console_error_panic_hook::set_once();
  #[cfg(debug_assertions)] console_log::init_with_level(log::Level::Debug).unwrap();
  info!("starting app");
  launch(app);
}

fn app(cx: Scope) -> Element {
  let site_path = get_path().unwrap();
  
  cx.render(rsx! {
    div {
      "We're here: ",
      {site_path}
    }
  })
}
