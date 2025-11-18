use codec::{Decode, Encode};
use polymesh_dart::AssetId;
use polymesh_dart::AssetState as NativeAssetState;
use wasm_bindgen::prelude::*;

use crate::keys::EncryptionPublicKey;

/// Helper function to convert chain key data (Uint8Array or hex strings) to EncryptionPublicKey objects
fn convert_chain_keys_to_encryption_keys(
    keys_value: JsValue,
) -> Result<Vec<EncryptionPublicKey>, JsValue> {
    let keys = js_sys::Array::from(&keys_value);
    let mut result = Vec::new();

    for i in 0..keys.length() {
        let key_data = keys.get(i);
        let key = EncryptionPublicKey::new(key_data)?;
        result.push(key);
    }

    Ok(result)
}

/// Represents the confidential asset state stored in the asset curve tree.
///
/// This type contains the asset's unique identifier and the encryption public keys
/// of all mediators and auditors associated with the asset. This information is needed
/// to encrypt settlement legs so that mediators and auditors can decrypt and verify
/// confidential transactions.
///
/// # Examples
/// ```javascript
/// // From Polkadot.js chain data (recommended)
/// const assetDetail = await api.query.confidentialAssets.dartAssetDetails(assetId);
/// const assetState = new AssetState(assetId, assetDetail.mediators, assetDetail.auditors);
///
/// // From pre-converted keys
/// const mediatorKey = new EncryptionPublicKey("0x1234...");
/// const auditorKey = new EncryptionPublicKey("0x5678...");
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
    /// Creates a new asset state from raw chain data or pre-converted encryption keys.
    ///
    /// This constructor automatically converts raw key data from various sources into
    /// `EncryptionPublicKey` objects. It's especially useful when querying the Polymesh chain
    /// for mediators and auditors using Polkadot.js, which returns keys as `Codec` objects
    /// with `.toU8a()` methods.
    ///
    /// # Arguments
    /// * `asset_id` - The unique identifier for this confidential asset (as a number).
    /// * `mediators` - Array of raw key data or `EncryptionPublicKey` objects. Each element can be:
    ///   - An existing `EncryptionPublicKey` object
    ///   - A `Uint8Array` (32 bytes)
    ///   - A hex string with or without "0x" prefix
    ///   - Any Polkadot.js `Codec` object with a `.toU8a()` method
    /// * `auditors` - Array of raw key data in the same formats as mediators.
    ///
    /// # Returns
    /// A new `AssetState` object.
    ///
    /// # Errors
    /// * Throws an error if any key cannot be decoded or is invalid.
    ///
    /// # Examples
    /// ```javascript
    /// // From Polkadot.js chain data (recommended)
    /// const assetDetail = await api.query.confidentialAssets.dartAssetDetails(assetId);
    /// const assetState = new AssetState(assetId, assetDetail.mediators, assetDetail.auditors);
    ///
    /// // From pre-converted EncryptionPublicKey objects
    /// const mediatorKey = new EncryptionPublicKey("0x1234...");
    /// const auditorKey = new EncryptionPublicKey("0x5678...");
    /// const assetState = new AssetState(assetId, [mediatorKey], [auditorKey]);
    ///
    /// // From hex strings or Uint8Arrays
    /// const assetState = new AssetState(assetId, ["0xabc..."], [new Uint8Array(32)]);
    ///
    /// // Use in settlement legs
    /// const leg = new LegBuilder(senderKeys, receiverKeys, assetState, amount);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(
        asset_id: AssetId,
        mediators: JsValue,
        auditors: JsValue,
    ) -> Result<AssetState, JsValue> {
        let mediator_keys = convert_chain_keys_to_encryption_keys(mediators)?;
        let auditor_keys = convert_chain_keys_to_encryption_keys(auditors)?;

        let mediator_inner: Vec<_> = mediator_keys.into_iter().map(|key| key.inner).collect();
        let auditor_inner: Vec<_> = auditor_keys.into_iter().map(|key| key.inner).collect();

        let inner = NativeAssetState::new(asset_id, &mediator_inner, &auditor_inner);

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
