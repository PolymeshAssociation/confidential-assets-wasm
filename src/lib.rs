use wasm_bindgen::prelude::*;

mod account;
mod asset;
mod keys;
mod settlement;
mod utils;

// Re-export main types
pub use account::*;
pub use asset::*;
pub use keys::*;
pub use settlement::*;

/// Initialize the WASM module. This should be called once when loading the module.
/// It sets up panic hooks for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    utils::set_panic_hook();
}

/// Get the version of the polymesh-dart-wasm library
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
