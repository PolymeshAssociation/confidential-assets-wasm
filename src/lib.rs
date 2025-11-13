use polymesh_dart::{Balance, SettlementRef};
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

/// Convert `JsValue` (String or 32 byte array) to `SettlementRef`
pub fn jsvalue_to_settlement_ref(value: &JsValue) -> Result<SettlementRef, JsValue> {
    let bytes = jsvalue_to_array::<32>(value)?;
    Ok(SettlementRef(bytes))
}

/// Convert `SettlementRef` to `JsValue` (hex string)
pub fn settlement_ref_to_jsvalue(settlement_ref: &SettlementRef) -> JsValue {
    JsValue::from_str(&format!("0x{}", hex::encode(settlement_ref.0)))
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
/// Accepts:
/// - JavaScript number (e.g., `1000`)
/// - JavaScript BigInt (e.g., `1000n`)
/// - Decimal string (e.g., `"1000"`)
/// - Hex string with 0x prefix (e.g., `"0x3e8"`)
pub fn jsvalue_to_balance(value: &JsValue) -> Result<Balance, JsValue> {
    // Try as number first
    if let Some(num) = value.as_f64() {
        if num < 0.0 || num > u64::MAX as f64 || num.fract() != 0.0 {
            return Err(JsValue::from_str(
                "Balance number must be a non-negative integer within u64 range",
            ));
        }
        return Ok(num as u64);
    }

    // Try as BigInt
    if let Ok(bigint) = js_sys::BigInt::new(value) {
        let bigint_str = format!("{}", bigint);

        log::info!("Convert JS BigInt to string: '{bigint_str}'");

        return bigint_str
            .parse::<u64>()
            .map_err(|e| JsValue::from_str(&format!("BigInt out of range for u64: {}", e)));
    }

    // Try as string (decimal or hex)
    if let Some(s) = value.as_string() {
        let s = s.trim();

        // Handle hex string
        if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex_str, 16)
                .map_err(|e| JsValue::from_str(&format!("Invalid hex balance: {}", e)));
        }

        // Handle decimal string
        return s
            .parse::<u64>()
            .map_err(|e| JsValue::from_str(&format!("Invalid decimal balance: {}", e)));
    }

    Err(JsValue::from_str(
        "Balance must be a number, BigInt, decimal string (e.g., \"1000\"), or hex string (e.g., \"0x3e8\")"
    ))
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
