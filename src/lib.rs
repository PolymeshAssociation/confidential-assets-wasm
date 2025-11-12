use polymesh_dart::Balance;
use wasm_bindgen::prelude::*;

use polymesh_api_client::{BlockHash, IdentityId};

pub mod error;
pub use error::*;

mod account;
mod asset;
mod client;
mod curve_tree;
mod keys;
mod settlement;
mod utils;

// Re-export main types
pub use account::*;
pub use asset::*;
pub use client::*;
pub use curve_tree::*;
pub use keys::*;
pub use settlement::*;

pub fn scale_convert<T1: codec::Encode, T2: codec::Decode>(t1: &T1) -> T2 {
    let buf = t1.encode();
    T2::decode(&mut &buf[..]).expect("The two types don't have compatible SCALE encoding")
}

/// Conver `JsValue` (String or `N` byte array) to `N` length array
pub fn jsvalue_to_array<const N: usize>(value: &JsValue) -> Result<[u8; N], JsValue> {
    if let Some(js_str) = value.as_string() {
        let off = if js_str.starts_with("0x") { 2 } else { 0 };
        if (js_str.len() - off) != N * 2 {
            return Err(JsValue::from_str(&format!(
                "Byte array must be {} bytes ({} hex characters)",
                N,
                N * 2
            )));
        }
        let mut array = [0u8; N];
        hex::decode_to_slice(&js_str[off..], &mut array).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode byte array from hex string: {}",
                e
            ))
        })?;
        Ok(array)
    } else {
        let uint8_array = js_sys::Uint8Array::new(value);
        if uint8_array.length() != N as u32 {
            return Err(JsValue::from_str(&format!(
                "Byte array must be {} bytes ({} hex characters)",
                N,
                N * 2
            )));
        }
        let mut array = [0u8; N];
        uint8_array.copy_to(&mut array);
        Ok(array)
    }
}

/// Convert JsValue (String or 32 byte array) to IdentityId
pub fn jsvalue_to_identity_id(value: &JsValue) -> Result<IdentityId, JsValue> {
    Ok(IdentityId(jsvalue_to_array(value)?))
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

/// Convert JS string or byte array to `Vec<u8>`
pub fn jsvalue_to_bytes(value: &JsValue) -> Result<Vec<u8>, JsValue> {
    if let Some(js_str) = value.as_string() {
        if js_str.starts_with("0x") {
            let bytes = hex::decode(js_str.trim_start_matches("0x")).map_err(|e| {
                JsValue::from_str(&format!("Failed to decode bytes from hex string: {}", e))
            })?;
            Ok(bytes)
        } else {
            Ok(js_str.as_bytes().to_vec())
        }
    } else {
        let uint8_array = js_sys::Uint8Array::new(value);
        let mut bytes = vec![0u8; uint8_array.length() as usize];
        uint8_array.copy_to(&mut bytes);
        Ok(bytes)
    }
}

/// Convert bytes to a JS string (if the bytes are valid UTF-8) or hex string
pub fn bytes_to_jsvalue(bytes: &[u8]) -> JsValue {
    match std::str::from_utf8(bytes) {
        Ok(s) => JsValue::from_str(s),
        Err(_) => JsValue::from_str(&format!("0x{}", hex::encode(bytes))),
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
