use codec::{Decode, Encode};
use polymesh_dart::AssetId;
use polymesh_dart::AssetState as NativeAssetState;
use wasm_bindgen::prelude::*;

use crate::keys::EncryptionPublicKey;

/// Represents the confidential asset state stored in the asset curve tree.
///
/// This type contains the asset's unique identifier and the encryption public keys
/// of all mediators and auditors associated with the asset. This information is needed
/// to encrypt settlement legs so that mediators and auditors can decrypt and verify
/// confidential transactions.
///
/// # Example
/// ```javascript
/// // Typically obtained from on-chain data
/// const assetState = await client.getAssetState(assetId);
///
/// // Or created manually if you have the mediator/auditor keys
/// const assetState = new AssetState(assetId, [mediatorKey], [auditorKey]);
///
/// // Use in settlement legs
/// const leg = new LegBuilder(senderKeys, receiverKeys, assetState, amount);
/// ```
#[wasm_bindgen]
#[derive(Clone, Debug, Encode, Decode)]
pub struct AssetState {
    pub(crate) inner: NativeAssetState,
}

#[wasm_bindgen]
impl AssetState {
    /// Creates a new asset state with the specified mediators and auditors.
    ///
    /// # Arguments
    /// * `asset_id` - The unique identifier for this confidential asset (as a number).
    /// * `mediators` - Array of `EncryptionPublicKey` objects for asset mediators who can decrypt and approve settlements.
    /// * `auditors` - Array of `EncryptionPublicKey` objects for asset auditors who can decrypt and monitor transactions.
    ///
    /// # Returns
    /// A new `AssetState` object.
    ///
    /// # Example
    /// ```javascript
    /// const mediatorKey = new EncryptionPublicKey("0x1234...");
    /// const auditorKey = new EncryptionPublicKey("0x5678...");
    /// const assetState = new AssetState(assetId, [mediatorKey], [auditorKey]);
    /// ```
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

    /// Serializes the asset state to a SCALE-encoded byte array.
    ///
    /// This allows you to store the asset state off-chain and restore it later.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded asset state.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = assetState.toBytes();
    /// localStorage.setItem('assetState', JSON.stringify(Array.from(bytes)));
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes asset state from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded asset state data.
    ///
    /// # Returns
    /// The deserialized `AssetState` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const storedBytes = JSON.parse(localStorage.getItem('assetState'));
    /// const assetState = AssetState.fromBytes(new Uint8Array(storedBytes));
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetState, JsValue> {
        let inner = NativeAssetState::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset state: {}", e)))?;
        Ok(AssetState { inner })
    }

    /// Gets the unique asset identifier.
    ///
    /// # Returns
    /// The asset ID as a number.
    ///
    /// # Example
    /// ```javascript
    /// const assetId = assetState.assetId();
    /// console.log('Asset ID:', assetId);
    /// ```
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id
    }

    /// Gets the leaf index of this asset in the asset curve tree.
    ///
    /// The leaf index is used to retrieve the asset's curve tree path for settlement proofs.
    /// Currently this is the same as the asset ID, but may change in future versions.
    ///
    /// # Returns
    /// The leaf index as a `bigint` (u64).
    ///
    /// # Example
    /// ```javascript
    /// const leafIndex = assetState.leafIndex();
    /// const path = await assetCurveTree.getLeafPath(leafIndex);
    /// settlementBuilder.addAssetPath(assetId, path);
    /// ```
    #[wasm_bindgen(js_name = leafIndex)]
    pub fn leaf_index(&self) -> u64 {
        self.inner.asset_id as _
    }

    /// Gets the number of mediators associated with this asset.
    ///
    /// # Returns
    /// The count of mediators as a number.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Mediators:', assetState.mediatorCount());
    /// ```
    #[wasm_bindgen(js_name = mediatorCount)]
    pub fn mediator_count(&self) -> usize {
        self.inner.mediators.len()
    }

    /// Gets the number of auditors associated with this asset.
    ///
    /// # Returns
    /// The count of auditors as a number.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Auditors:', assetState.auditorCount());
    /// ```
    #[wasm_bindgen(js_name = auditorCount)]
    pub fn auditor_count(&self) -> usize {
        self.inner.auditors.len()
    }

    /// Exports the asset state as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the asset state.
    ///
    /// # Errors
    /// * Throws an error if serialization to JSON fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Asset State:', assetState.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}
