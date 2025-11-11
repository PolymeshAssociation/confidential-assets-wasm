use codec::{Decode, Encode};
use polymesh_dart::AssetId;
use polymesh_dart::AssetState as NativeAssetState;
use wasm_bindgen::prelude::*;

use crate::keys::EncryptionPublicKey;

/// Asset state (stored in the asset tree)
#[wasm_bindgen]
#[derive(Clone, Debug, Encode, Decode)]
pub struct AssetState {
    pub(crate) inner: NativeAssetState,
}

#[wasm_bindgen]
impl AssetState {
    /// Create a new asset state
    #[wasm_bindgen(constructor)]
    pub fn new(
        asset_id: AssetId,
        mediators: Vec<EncryptionPublicKey>,
        auditors: Vec<EncryptionPublicKey>,
    ) -> Result<AssetState, JsValue> {
        // Convert JsValue arrays to EncryptionPublicKey vectors
        let mediator_keys: Vec<_> = mediators.into_iter().map(|js| js.inner).collect();

        let auditor_keys: Vec<_> = auditors.into_iter().map(|js| js.inner).collect();

        let inner = NativeAssetState::new(asset_id, &mediator_keys, &auditor_keys);

        Ok(AssetState { inner })
    }

    /// Export asset state as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import asset state from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetState, JsValue> {
        let inner = NativeAssetState::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset state: {}", e)))?;
        Ok(AssetState { inner })
    }

    /// Get the asset ID
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id
    }

    /// Get the number of mediators
    #[wasm_bindgen(js_name = mediatorCount)]
    pub fn mediator_count(&self) -> usize {
        self.inner.mediators.len()
    }

    /// Get the number of auditors
    #[wasm_bindgen(js_name = auditorCount)]
    pub fn auditor_count(&self) -> usize {
        self.inner.auditors.len()
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}
