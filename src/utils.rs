/// Utilities for WASM bindings

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Convert a JsValue error to a wasm_bindgen error
#[allow(dead_code)]
pub fn to_js_error<E: std::fmt::Display>(error: E) -> wasm_bindgen::JsValue {
    js_sys::Error::new(&format!("{}", error)).into()
}
