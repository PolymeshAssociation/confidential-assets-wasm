use codec::{Decode, Encode};
use polymesh_dart::{
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountAssetState as NativeAccountAssetState, AccountState as NativeAccountState,
    AssetMintingProof as NativeAssetMintingProof,
};
use polymesh_dart::{AssetId, Balance};
use wasm_bindgen::prelude::*;

/// Account state for a specific asset
#[wasm_bindgen]
#[derive(Clone)]
pub struct AccountAssetState {
    pub(crate) inner: NativeAccountAssetState,
}

impl AccountAssetState {
    pub fn new(inner: NativeAccountAssetState) -> Self {
        AccountAssetState { inner }
    }
}

#[wasm_bindgen]
impl AccountAssetState {
    /// Export account asset state as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import account asset state from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountAssetState, JsValue> {
        let inner = NativeAccountAssetState::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode account asset state: {}", e))
        })?;
        Ok(AccountAssetState { inner })
    }

    /// Get the asset ID for this account state
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id()
    }

    /// Get the current balance
    #[wasm_bindgen(js_name = balance)]
    pub fn balance(&self) -> Balance {
        self.inner.current_state.balance
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Account state (the commitment value stored in the account tree)
#[wasm_bindgen]
pub struct AccountState {
    pub(crate) inner: NativeAccountState,
}

impl AccountState {
    pub fn new(inner: NativeAccountState) -> Self {
        AccountState { inner }
    }
}

#[wasm_bindgen]
impl AccountState {
    /// Export account state as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import account state from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountState, JsValue> {
        let inner = NativeAccountState::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode account state: {}", e)))?;
        Ok(AccountState { inner })
    }

    /// Get the asset ID
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id
    }

    /// Get the balance
    #[wasm_bindgen(js_name = balance)]
    pub fn balance(&self) -> Balance {
        self.inner.balance
    }

    /// Get the pending transaction counter
    #[wasm_bindgen(js_name = counter)]
    pub fn counter(&self) -> u64 {
        self.inner.counter
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Proof of account registration for a specific asset
#[wasm_bindgen]
pub struct AccountAssetRegistrationProof {
    pub(crate) inner: NativeAccountAssetRegistrationProof,
}

#[wasm_bindgen]
impl AccountAssetRegistrationProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountAssetRegistrationProof, JsValue> {
        let inner = NativeAccountAssetRegistrationProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode registration proof: {}", e))
        })?;
        Ok(AccountAssetRegistrationProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<AccountAssetRegistrationProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of asset minting
#[wasm_bindgen]
pub struct AssetMintingProof {
    pub(crate) inner: NativeAssetMintingProof,
}

#[wasm_bindgen]
impl AssetMintingProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetMintingProof, JsValue> {
        let inner = NativeAssetMintingProof::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode minting proof: {}", e)))?;
        Ok(AssetMintingProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<AssetMintingProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}
