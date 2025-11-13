use futures_util::StreamExt;

use polymesh_api::Api;
use polymesh_api_client::{DefaultSigner, Signer};
use polymesh_dart::{AssetId, AssetState as NativeAssetState, WrappedCanonical};
use wasm_bindgen::prelude::*;

use crate::curve_tree::{AccountLeafPathAndRoot, AssetLeafPathAndRoot, FeeAccountLeafPathAndRoot};
use crate::keys::AccountPublicKey;
use crate::{
    identity_id_to_jsvalue, jsvalue_to_settlement_ref, scale_convert, AssetLeafPath, AssetState,
    AssetTreeRoot, SettlementLegsEncrypted,
};

mod curve_tree;
pub mod signer;

pub use signer::*;

/// A client connection to a Polymesh node
#[wasm_bindgen]
pub struct PolymeshClient {
    pub(crate) api: Api,
}

#[wasm_bindgen]
impl PolymeshClient {
    /// Connect to a Polymesh node at the given URL
    ///
    /// # Arguments
    /// * `url` - The WebSocket URL of the Polymesh node to connect to
    ///
    /// # Returns
    /// A `PolymeshClient` instance connected to the specified node
    ///
    /// # Errors
    /// Returns a `JsValue` error if the connection to the node fails
    ///
    /// # Examples
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// ```
    #[wasm_bindgen]
    pub async fn connect(url: &str) -> Result<Self, JsValue> {
        let url = url.to_string();
        let api = Api::new(&url)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to connect to node: {}", e)))?;
        Ok(PolymeshClient { api })
    }

    /// Get a handle for the Asset curve tree.
    #[wasm_bindgen(js_name = getAssetCurveTree)]
    pub async fn get_asset_curve_tree(&self) -> Result<AssetCurveTree, JsValue> {
        let tree = curve_tree::AssetCurveTree::new(&self.api)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset curve tree: {}", e)))?;
        Ok(AssetCurveTree { inner: tree })
    }

    /// Get a handle for the Account curve tree.
    #[wasm_bindgen(js_name = getAccountCurveTree)]
    pub async fn get_account_curve_tree(&self) -> Result<AccountCurveTree, JsValue> {
        let tree = curve_tree::AccountCurveTree::new(&self.api)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get account curve tree: {}", e)))?;
        Ok(AccountCurveTree { inner: tree })
    }

    /// Get a handle for the Fee Account curve tree.
    #[wasm_bindgen(js_name = getFeeAccountCurveTree)]
    pub async fn get_fee_account_curve_tree(&self) -> Result<FeeAccountCurveTree, JsValue> {
        let tree = curve_tree::FeeAccountCurveTree::new(&self.api)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to get fee account curve tree: {}", e))
            })?;
        Ok(FeeAccountCurveTree { inner: tree })
    }

    /// Create a new signer from the given string.
    ///
    /// The string can be in any format supported by `subxt_signer::ecdsa::Keypair::from_uri`,
    /// such as a mnemonic phrase or raw private key.
    #[wasm_bindgen(js_name = newSigner)]
    pub fn new_signer(&self, s: &str) -> Result<PolymeshSigner, JsValue> {
        let signer = DefaultSigner::from_string(s, None)
            .map_err(|e| JsValue::from_str(&format!("Failed to create signer: {}", e)))?;
        Ok(PolymeshSigner::new(signer, &self.api))
    }

    /// Onboard a new signer (CDD + POLYX funding).
    ///
    /// This is only supported on a development/test chains.
    #[wasm_bindgen(js_name = onboardSigner)]
    pub async fn onboard_signer(&self, new_signer: &PolymeshSigner) -> Result<(), JsValue> {
        let account_id = new_signer.signer.account();
        // Use `Alice` to onboard the new signer
        let mut alice = PolymeshSigner::alice(&self.api);

        alice
            .onboard_signer(account_id)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to onboard signer: {}", e)))?;

        Ok(())
    }

    /// Get the identity of a give account public key, if any.
    ///
    /// The identity DID is returned as a 32 byte array.
    #[wasm_bindgen(js_name = getAccountIdentity)]
    pub async fn get_account_identity(
        &self,
        account: &AccountPublicKey,
    ) -> Result<JsValue, JsValue> {
        let identity = self
            .api
            .query()
            .confidential_assets()
            .account_did(scale_convert(&account.inner))
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query identity: {}", e)))?;

        match identity {
            Some(did) => Ok(identity_id_to_jsvalue(&did)),
            None => Ok(JsValue::NULL),
        }
    }

    /// Get an asset's `AssetState` by its Asset ID.
    #[wasm_bindgen(js_name = getAssetState)]
    pub async fn get_asset_state(&self, asset_id: AssetId) -> Result<AssetState, JsValue> {
        // Get DART asset details.
        let details = self
            .api
            .query()
            .confidential_assets()
            .dart_asset_details(asset_id)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to query DART asset details for Asset ID {}: {}",
                    asset_id, e
                ))
            })?
            .ok_or_else(|| {
                JsValue::from_str(&format!("No DART asset found for Asset ID {}", asset_id))
            })?;
        Ok(AssetState {
            inner: NativeAssetState {
                asset_id,
                auditors: scale_convert(&details.auditors),
                mediators: scale_convert(&details.mediators),
            },
        })
    }

    /// Get settlement encrypted legs.
    #[wasm_bindgen(js_name = getSettlementLegs)]
    pub async fn get_settlement_legs(
        &self,
        settlement_ref: JsValue,
    ) -> Result<SettlementLegsEncrypted, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let entries = self
            .api
            .paged_query()
            .confidential_assets()
            .settlement_legs(scale_convert(&settlement_ref))
            .entries();
        tokio::pin!(entries);

        let mut legs = Vec::new();
        while let Some(entry) = entries.next().await {
            let (_key, leg) = entry.map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to query settlement legs for settlement ID {:?}: {}",
                    settlement_ref, e
                ))
            })?;
            if let Some(leg) = leg {
                legs.push(scale_convert(&leg));
            } else {
                break;
            }
        }

        Ok(SettlementLegsEncrypted { inner: legs })
    }
}

/// The Fee Account curve tree.
#[wasm_bindgen]
pub struct FeeAccountCurveTree {
    pub(crate) inner: curve_tree::FeeAccountCurveTree,
}

#[wasm_bindgen]
impl FeeAccountCurveTree {
    /// Get fee account leaf path and root.
    ///
    /// If no block number is provided, the latest root is used.
    #[wasm_bindgen(js_name = getLeafPathAndRoot)]
    pub async fn get_leaf_path_and_root(
        &self,
        leaf_index: u64,
        block_number: Option<u32>,
    ) -> Result<FeeAccountLeafPathAndRoot, JsValue> {
        log::info!(
            "get_leaf_path_and_root called with leaf_index: {}, block_number: {:?}",
            leaf_index,
            block_number
        );
        let path = self
            .inner
            .get_path_and_root(leaf_index, block_number)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to get fee account leaf path: {}", e))
            })?;

        Ok(FeeAccountLeafPathAndRoot { path })
    }

    /// Get the block number of the last updated root.
    #[wasm_bindgen(js_name = getLastBlockNumber)]
    pub async fn get_last_block_number(&self) -> Result<u32, JsValue> {
        let block_number = self.inner.get_block_number().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to get last block number of fee account curve tree: {}",
                e
            ))
        })?;

        Ok(block_number)
    }
}

/// The Account curve tree.
#[wasm_bindgen]
pub struct AccountCurveTree {
    pub(crate) inner: curve_tree::AccountCurveTree,
}

#[wasm_bindgen]
impl AccountCurveTree {
    /// Get account leaf path and root.
    ///
    /// If no block number is provided, the latest root is used.
    #[wasm_bindgen(js_name = getLeafPathAndRoot)]
    pub async fn get_leaf_path_and_root(
        &self,
        leaf_index: u64,
        block_number: Option<u32>,
    ) -> Result<AccountLeafPathAndRoot, JsValue> {
        log::info!(
            "get_leaf_path_and_root called with leaf_index: {}, block_number: {:?}",
            leaf_index,
            block_number
        );
        let path = self
            .inner
            .get_path_and_root(leaf_index, block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get account leaf path: {}", e)))?;

        Ok(AccountLeafPathAndRoot { path })
    }

    /// Get the block number of the last updated root.
    #[wasm_bindgen(js_name = getLastBlockNumber)]
    pub async fn get_last_block_number(&self) -> Result<u32, JsValue> {
        let block_number = self.inner.get_block_number().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to get last block number of account curve tree: {}",
                e
            ))
        })?;
        Ok(block_number)
    }
}

/// The Asset curve tree.
#[wasm_bindgen]
pub struct AssetCurveTree {
    pub(crate) inner: curve_tree::AssetCurveTree,
}

#[wasm_bindgen]
impl AssetCurveTree {
    /// Get asset leaf path and root.
    ///
    /// If no block number is provided, the latest root is used.
    #[wasm_bindgen(js_name = getLeafPathAndRoot)]
    pub async fn get_leaf_path_and_root(
        &self,
        leaf_index: u64,
        block_number: Option<u32>,
    ) -> Result<AssetLeafPathAndRoot, JsValue> {
        log::info!(
            "get_leaf_path_and_root called with leaf_index: {}, block_number: {:?}",
            leaf_index,
            block_number
        );
        let path = self
            .inner
            .get_path_and_root(leaf_index, block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset leaf path: {}", e)))?;

        Ok(AssetLeafPathAndRoot { path })
    }

    /// Get the block number of the last updated root.
    #[wasm_bindgen(js_name = getLastBlockNumber)]
    pub async fn get_last_block_number(&self) -> Result<u32, JsValue> {
        let block_number = self.inner.get_block_number().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to get last block number of asset curve tree: {}",
                e
            ))
        })?;
        log::info!(
            "get_last_block_number returning block_number: {}",
            block_number
        );
        Ok(block_number)
    }

    /// Get the Asset tree root.
    #[wasm_bindgen(js_name = getRoot)]
    pub async fn get_root(&self, block_number: Option<u32>) -> Result<AssetTreeRoot, JsValue> {
        log::info!("get_root called with block_number: {:?}", block_number);
        let root = self
            .inner
            .fetch_root(block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset tree root: {}", e)))?;
        Ok(AssetTreeRoot { root })
    }

    /// Get asset leaf path.
    ///
    /// If no block number is provided, the latest root is used.
    #[wasm_bindgen(js_name = getLeafPath)]
    pub async fn get_leaf_path(
        &self,
        leaf_index: u64,
        block_number: Option<u32>,
    ) -> Result<AssetLeafPath, JsValue> {
        log::info!(
            "get_leaf_path called with leaf_index: {}, block_number: {:?}",
            leaf_index,
            block_number
        );
        let path = self
            .inner
            .get_path_to_leaf(leaf_index, 0, block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset leaf path: {}", e)))?;
        Ok(AssetLeafPath {
            path: WrappedCanonical::wrap(&path).map_err(|e| {
                JsValue::from_str(&format!("Failed to wrap asset leaf path: {}", e))
            })?,
        })
    }
}
