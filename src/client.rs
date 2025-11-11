use std::ops::Deref;

use polymesh_api::Api;
use polymesh_api_client::{DefaultSigner, Signer};
use wasm_bindgen::prelude::*;

use crate::keys::AccountPublicKey;
use crate::{identity_id_to_jsvalue, scale_convert, AssetState};

pub mod curve_tree;
pub mod signer;

pub use curve_tree::*;
pub use signer::*;

/// A client connection to a Polymesh node
#[wasm_bindgen]
pub struct PolymeshClient {
    pub(crate) api: Api,
}

#[wasm_bindgen]
impl PolymeshClient {
    /// Connect to a Polymesh node at the given URL
    #[wasm_bindgen(constructor)]
    pub fn new(url: &str) -> js_sys::Promise {
        let url = url.to_string();
        wasm_bindgen_futures::future_to_promise(async move {
            let api = Api::new(&url)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to connect to node: {}", e)))?;
            Ok(JsValue::from(PolymeshClient { api }))
        })
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
}

/// Fee account leaf path and root.
#[wasm_bindgen]
pub struct FeeAccountLeafPath {
    pub(crate) path: curve_tree::FeeAccountLeafPath,
}

impl Deref for FeeAccountLeafPath {
    type Target = curve_tree::FeeAccountLeafPath;

    fn deref(&self) -> &Self::Target {
        &self.path
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
    #[wasm_bindgen(js_name = getFeeAccountLeafPath)]
    pub async fn get_fee_account_leaf_path(
        &self,
        leaf_index: u64,
    ) -> Result<FeeAccountLeafPath, JsValue> {
        let path = self
            .inner
            .get_path_and_root(leaf_index)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to get fee account leaf path: {}", e))
            })?;

        Ok(FeeAccountLeafPath { path })
    }
}

/// Account leaf path and root.
#[wasm_bindgen]
pub struct AccountLeafPath {
    pub(crate) path: curve_tree::AccountLeafPath,
}

impl Deref for AccountLeafPath {
    type Target = curve_tree::AccountLeafPath;

    fn deref(&self) -> &Self::Target {
        &self.path
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
    #[wasm_bindgen(js_name = getAccountLeafPath)]
    pub async fn get_account_leaf_path(&self, leaf_index: u64) -> Result<AccountLeafPath, JsValue> {
        let path = self
            .inner
            .get_path_and_root(leaf_index)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get account leaf path: {}", e)))?;

        Ok(AccountLeafPath { path })
    }
}

/// The Asset curve tree.
#[wasm_bindgen]
pub struct AssetCurveTree {
    pub(crate) inner: curve_tree::AssetCurveTree,
}

#[wasm_bindgen]
impl AssetCurveTree {
    /// Asset Leaf paths builder.
    #[wasm_bindgen(js_name = buildAssetLeafPaths)]
    pub async fn build_asset_leaf_paths(&self) -> Result<AssetLeafPaths, JsValue> {
        let paths = curve_tree::AssetLeafPaths::new(&self.inner)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset leaf paths: {}", e)))?;

        Ok(AssetLeafPaths {
            paths,
            tree: self.inner.clone(),
        })
    }
}

/// Asset Leaf paths
#[wasm_bindgen]
pub struct AssetLeafPaths {
    pub(crate) paths: curve_tree::AssetLeafPaths,
    pub(crate) tree: curve_tree::AssetCurveTree,
}

#[wasm_bindgen]
impl AssetLeafPaths {
    /// Track asset path and get the asset state.
    #[wasm_bindgen(js_name = trackAsset)]
    pub async fn track_asset(&mut self, asset_id: u32) -> Result<AssetState, JsValue> {
        // track asset id
        let api = &self.tree.backend.api;
        let state = self
            .paths
            .track_asset(asset_id, &self.tree, api)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to track asset id: {}", e)))?;

        Ok(AssetState { inner: state })
    }
}
