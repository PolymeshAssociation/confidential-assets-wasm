use polymesh_dart::Balance;
use wasm_bindgen::prelude::*;

use polymesh_api_client::{BlockHash, IdentityId};

pub mod error;
pub use error::*;

mod account;
mod asset;
mod client;
mod keys;
mod settlement;
mod utils;

// Re-export main types
pub use account::*;
pub use asset::*;
pub use client::*;
pub use keys::*;
pub use settlement::*;

pub fn scale_convert<T1: codec::Encode, T2: codec::Decode>(t1: &T1) -> T2 {
    let buf = t1.encode();
    T2::decode(&mut &buf[..]).expect("The two types don't have compatible SCALE encoding")
}

/// Convert JsValue (String or 32 byte array) to IdentityId
pub fn jsvalue_to_identity_id(value: &JsValue) -> Result<IdentityId, JsValue> {
    if let Some(js_str) = value.as_string() {
        let bytes = hex::decode(js_str.trim_start_matches("0x")).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode IdentityId from hex string: {}",
                e
            ))
        })?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str(
                "IdentityId must be 32 bytes (64 hex characters)",
            ));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(IdentityId(array))
    } else {
        let uint8_array = js_sys::Uint8Array::new(value);
        if uint8_array.length() != 32 {
            return Err(JsValue::from_str(
                "IdentityId must be 32 bytes (64 hex characters)",
            ));
        }
        let mut array = [0u8; 32];
        uint8_array.copy_to(&mut array);
        Ok(IdentityId(array))
    }
}

/// Convert IdentityId to JsValue (hex string)
pub fn identity_id_to_jsvalue(did: &IdentityId) -> JsValue {
    JsValue::from_str(&format!("0x{}", hex::encode(did.0)))
}

/// Convert `BlockHash` to `JsValue`
pub fn block_hash_to_jsvalue(hash: Option<BlockHash>) -> JsValue {
    match hash {
        Some(h) => JsValue::from_str(&h.to_string()),
        None => JsValue::NULL,
    }
}

/// Convert `JsValue` to `Balance`
///
/// Convert js number to u64 Balance.
pub fn jsvalue_to_balance(value: &JsValue) -> Result<Balance, JsValue> {
    let num = value
        .as_f64()
        .ok_or_else(|| JsValue::from_str("Balance must be a number representable as u64"))?;
    if num < 0.0 || num > u64::MAX as f64 {
        return Err(JsValue::from_str("Balance out of range for u64"));
    }
    Ok(num as u64)
}

/// Convert `Balance` to `JsValue`
pub fn balance_to_jsvalue(balance: Balance) -> JsValue {
    JsValue::from_f64(balance as f64)
}

/// Initialize the WASM module. This should be called once when loading the module.
/// It sets up panic hooks for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    wasm_logger::init(wasm_logger::Config::default());
    utils::set_panic_hook();
}

/// Get the version of the polymesh-dart-wasm library
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
