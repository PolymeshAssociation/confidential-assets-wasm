use codec::{Decode, Encode};
use polymesh_dart::AssetId;
use polymesh_dart::{
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountAssetState as NativeAccountAssetState, AccountState as NativeAccountState,
    AssetMintingProof as NativeAssetMintingProof,
};
use wasm_bindgen::prelude::*;

use crate::{balance_to_jsvalue, jsvalue_to_balance, AccountKeys, AccountLeafPath};

/// Account state for a specific asset
#[wasm_bindgen]
#[derive(Clone, Debug, Encode, Decode)]
pub struct AccountAssetState {
    pub(crate) inner: NativeAccountAssetState,
    pub(crate) leaf_index: u64,
}

impl AccountAssetState {
    pub fn new(inner: NativeAccountAssetState) -> Self {
        AccountAssetState {
            inner,
            leaf_index: u64::MAX,
        }
    }
}

#[wasm_bindgen]
impl AccountAssetState {
    /// Export account asset state as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    /// Import account asset state from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountAssetState, JsValue> {
        let state = AccountAssetState::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode account asset state: {}", e))
        })?;
        Ok(state)
    }

    /// Get the asset ID for this account state
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id()
    }

    // Get the leaf index in the account curve tree
    #[wasm_bindgen(js_name = leafIndex)]
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    // Commit the pending state to the current state and update the leaf index
    #[wasm_bindgen(js_name = commitPendingState)]
    pub fn commit_pending_state(&mut self, leaf_index: u64) {
        if leaf_index == u64::MAX {
            // Remove pending state without committing
            self.inner.pending_state = None;
        } else {
            self.inner
                .commit_pending_state()
                .expect("Failed to commit pending state");
            self.leaf_index = leaf_index;
        }
    }

    // Is there a pending state?
    #[wasm_bindgen(js_name = hasPendingState)]
    pub fn has_pending_state(&self) -> bool {
        self.inner.pending_state.is_some()
    }

    /// Get the current balance
    #[wasm_bindgen(js_name = balance)]
    pub fn balance(&self) -> JsValue {
        balance_to_jsvalue(self.inner.current_state.balance)
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }

    /// Generate an asset minting proof for this account
    #[wasm_bindgen(js_name = assetMintingProof)]
    pub fn asset_minting_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPath,
        amount: JsValue,
    ) -> Result<AssetMintingProof, JsValue> {
        let amount = jsvalue_to_balance(&amount)?;
        let mut rng = rand::rngs::OsRng;
        let account = &keys.inner.acct;

        let proof =
            NativeAssetMintingProof::new(&mut rng, account, &mut self.inner, &path.path, amount)
                .map_err(|e| {
                    JsValue::from_str(&format!("Failed to generate asset minting proof: {}", e))
                })?;

        Ok(AssetMintingProof { inner: proof })
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
    pub fn balance(&self) -> JsValue {
        balance_to_jsvalue(self.inner.balance)
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

/// The Account asset registration proof and resulting account asset state
/// generated when registering an account for a specific asset.
#[wasm_bindgen]
pub struct AccountAssetRegistration {
    pub(crate) proof: NativeAccountAssetRegistrationProof,
    pub(crate) state: AccountAssetState,
}

#[wasm_bindgen]
impl AccountAssetRegistration {
    /// Get the registration proof
    #[wasm_bindgen(js_name = getProof)]
    pub fn get_proof(&self) -> AccountAssetRegistrationProof {
        AccountAssetRegistrationProof {
            inner: self.proof.clone(),
        }
    }

    /// Get the registration proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = getProofBytes)]
    pub fn get_proof_bytes(&self) -> Vec<u8> {
        self.proof.encode()
    }

    /// Get the resulting account asset state
    #[wasm_bindgen(js_name = getAccountAssetState)]
    pub fn get_account_asset_state(&self) -> AccountAssetState {
        self.state.clone()
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
