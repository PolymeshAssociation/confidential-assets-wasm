use wasm_bindgen::prelude::*;

pub mod error;
pub use error::*;

mod account;
mod asset;
mod curve_tree;
mod keys;
mod settlement;
mod utils;

// Re-export main types
pub use account::*;
pub use asset::*;
pub use curve_tree::*;
pub use keys::*;
pub use settlement::*;

pub fn scale_convert<T1: codec::Encode, T2: codec::Decode>(t1: &T1) -> T2 {
    let buf = t1.encode();
    T2::decode(&mut &buf[..]).expect("The two types don't have compatible SCALE encoding")
}

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
