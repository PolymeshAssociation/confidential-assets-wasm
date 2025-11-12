use codec::{Decode, Encode};

use wasm_bindgen::prelude::*;

use polymesh_dart::{
    curve_tree::{
        AccountTreeConfig, AssetTreeConfig, CompressedCurveTreeRoot, CompressedInner,
        CompressedLeafValue, CurveTreeLookup, CurveTreePath, FeeAccountTreeConfig, LeafPathAndRoot,
        NodeLocation,
    },
    WrappedCanonical, ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M,
    FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M,
};

pub type NativeAssetLeaf = CompressedLeafValue<AssetTreeConfig>;
pub type NativeAssetLeafPath = WrappedCanonical<CurveTreePath<ASSET_TREE_L, AssetTreeConfig>>;
pub type NativeAssetLeafPathAndRoot = LeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;
pub type NativeAssetInnerNode = CompressedInner<ASSET_TREE_M, AssetTreeConfig>;
pub type NativeAssetNodeLocation = NodeLocation<ASSET_TREE_L>;
pub type NativeAssetTreeRoot = CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

pub type NativeAccountLeaf = CompressedLeafValue<AccountTreeConfig>;
pub type NativeAccountLeafPath = WrappedCanonical<CurveTreePath<ACCOUNT_TREE_L, AccountTreeConfig>>;
pub type NativeAccountLeafPathAndRoot =
    LeafPathAndRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;
pub type NativeAccountInnerNode = CompressedInner<ACCOUNT_TREE_M, AccountTreeConfig>;
pub type NativeAccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;
pub type NativeAccountTreeRoot =
    CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

pub type NativeFeeAccountLeaf = CompressedLeafValue<FeeAccountTreeConfig>;
pub type NativeFeeAccountLeafPath =
    WrappedCanonical<CurveTreePath<FEE_ACCOUNT_TREE_L, FeeAccountTreeConfig>>;
pub type NativeFeeAccountLeafPathAndRoot =
    LeafPathAndRoot<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;
pub type NativeFeeAccountInnerNode = CompressedInner<FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;
pub type NativeFeeAccountNodeLocation = NodeLocation<FEE_ACCOUNT_TREE_L>;
pub type NativeFeeAccountTreeRoot =
    CompressedCurveTreeRoot<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;

/// Fee account leaf path and root.
#[wasm_bindgen]
pub struct FeeAccountLeafPathAndRoot {
    pub(crate) path: NativeFeeAccountLeafPathAndRoot,
}

#[wasm_bindgen]
impl FeeAccountLeafPathAndRoot {
    /// Export the path and root as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Import the path and root from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<FeeAccountLeafPathAndRoot, JsValue> {
        let path = Decode::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode fee account leaf path and root: {}",
                e
            ))
        })?;
        Ok(FeeAccountLeafPathAndRoot { path })
    }
}

/// Account leaf path and root.
#[wasm_bindgen]
pub struct AccountLeafPathAndRoot {
    pub(crate) path: NativeAccountLeafPathAndRoot,
}

#[wasm_bindgen]
impl AccountLeafPathAndRoot {
    /// Export the path and root as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Import the path and root from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<FeeAccountLeafPathAndRoot, JsValue> {
        let path = Decode::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode account leaf path and root: {}",
                e
            ))
        })?;
        Ok(FeeAccountLeafPathAndRoot { path })
    }
}

/// Asset leaf path and root.
#[wasm_bindgen]
pub struct AssetLeafPathAndRoot {
    pub(crate) path: NativeAssetLeafPathAndRoot,
}

#[wasm_bindgen]
impl AssetLeafPathAndRoot {
    /// Export the path and root as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Import the path and root from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetLeafPathAndRoot, JsValue> {
        let path = Decode::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode asset leaf path and root: {}", e))
        })?;
        Ok(AssetLeafPathAndRoot { path })
    }

    /// Get the Asset tree root.
    #[wasm_bindgen(js_name = getRoot)]
    pub fn get_root(&self) -> Result<AssetTreeRoot, JsValue> {
        let root = self
            .path
            .root()
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset tree root: {}", e)))?;
        Ok(AssetTreeRoot { root })
    }

    /// Get the block number of the root.
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> Result<u32, JsValue> {
        self.path
            .get_block_number()
            .map_err(|e| JsValue::from_str(&format!("Failed to get block number: {}", e)))
    }
}

/// Asset tree root.
#[wasm_bindgen]
pub struct AssetTreeRoot {
    pub(crate) root: NativeAssetTreeRoot,
}

#[wasm_bindgen]
impl AssetTreeRoot {
    /// Export the root as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.root.encode()
    }

    /// Import the root from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetTreeRoot, JsValue> {
        let root = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset tree root: {}", e)))?;
        Ok(AssetTreeRoot { root })
    }
}

/// Asset leaf path.
#[wasm_bindgen]
pub struct AssetLeafPath {
    pub(crate) path: NativeAssetLeafPath,
}

#[wasm_bindgen]
impl AssetLeafPath {
    /// Export the path as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Import the path from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetLeafPath, JsValue> {
        let path = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset leaf path: {}", e)))?;
        Ok(AssetLeafPath { path })
    }
}
