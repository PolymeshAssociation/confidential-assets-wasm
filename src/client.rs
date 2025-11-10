use polymesh_api::Api;
use wasm_bindgen::prelude::*;

use crate::AssetState;

pub mod curve_tree;

/// A client connection to a Polymesh node
#[wasm_bindgen]
pub struct PolymeshClient {
    pub(crate) inner: Api,
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
            Ok(JsValue::from(PolymeshClient { inner: api }))
        })
    }

    /// Get a handle for the Asset curve tree.
    #[wasm_bindgen(js_name = getAssetCurveTree)]
    pub async fn get_asset_curve_tree(&self) -> Result<AssetCurveTree, JsValue> {
        let tree = curve_tree::AssetCurveTree::new(&self.inner)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset curve tree: {}", e)))?;
        Ok(AssetCurveTree { inner: tree })
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
