use std::collections::{BTreeMap, BTreeSet};

use codec::{Decode, Encode};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use polymesh_dart::{
    curve_tree::{
        AccountTreeConfig, AssetTreeConfig, CompressedCurveTreeRoot, CompressedInner,
        CompressedLeafValue, CurveTreeBackend, CurveTreeConfig, CurveTreeLookup, CurveTreePath,
        CurveTreeWithBackend, DefaultCurveTreeUpdater, FeeAccountTreeConfig, LeafPathAndRoot,
        NodeLocation, SelRerandParameters,
    },
    BlockNumber, ChildIndex, LeafIndex, NodeLevel, WrappedCanonical, ACCOUNT_TREE_L,
    ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M, FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M,
};

use crate::Error;

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

    /// Get the block number of the root.
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> Result<u32, JsValue> {
        self.path
            .get_block_number()
            .map_err(|e| JsValue::from_str(&format!("Failed to get block number: {}", e)))
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

/// LeafPathBuilder
///
/// 1. JS creates a LeafPathBuilder object using the leaf index: `const pathBuilder = new LeafPathBuilder(leafIndex, height, block_number);`
/// 2. Get the list of node locations to query from the chain: `const nodeLocations = pathBuilder.getLocations();`
/// 3. JS queries the chain for those locations: `const nodes = apiAt.query.confidentialAssets.accountInnerNodes.multi(nodeLocations);`
/// 4. Calculate the sibling leaf indices: `const leafIndices = pathBuilder.getSiblingLeafIndices();`
/// 5. JS queries the chain for the sibling leaves: `const siblingLeaves = apiAt.query.confidentialAssets.accountLeaves.multi(leafIndices);`
/// 6. JS queries the chain for the the tree root: `const root = apiAt.query.confidentialAssets.accountCurveTreeRoots(block_number);`
/// 7. Build the path with root: `const path_and_root = pathBuilder.build_with_root(root, leaves, nodes);`
/// 8. Build only the path: `const path = pathBuilder.build(leaves, nodes);`
#[derive(Clone, Debug)]
pub struct LeafPathBuilder<const L: usize, const M: usize, C: CurveTreeConfig> {
    pub leaf_index: LeafIndex,
    pub height: NodeLevel,
    pub block_number: BlockNumber,
    pub node_locations: Vec<NodeLocation<L>>,
    pub nodes: BTreeMap<NodeLocation<L>, CompressedInner<M, C>>,
    pub leaves: BTreeMap<LeafIndex, CompressedLeafValue<C>>,
    pub leaf_range: (LeafIndex, LeafIndex),
    pub leaf_indices: Vec<LeafIndex>,
    pub root: Option<Vec<u8>>,
}

fn calculate_node_locations<const L: usize>(
    leaf_index: LeafIndex,
    height: NodeLevel,
) -> (Vec<NodeLocation<L>>, Vec<LeafIndex>, (LeafIndex, LeafIndex)) {
    let mut node_locations = BTreeSet::new();
    let mut leaf_indices = Vec::with_capacity(L);
    let mut min_leaf_index = leaf_index;
    let mut max_leaf_index = leaf_index;

    // Start at the leaf's location.
    let mut location = NodeLocation::<L>::leaf(leaf_index);

    while !location.is_root(height) {
        let (parent, _) = location.parent();
        // Insert the parent location.
        node_locations.insert(parent.clone());
        // Insert all of the children locations.
        for idx in 0..L {
            let child = parent
                .child(idx as ChildIndex)
                .expect("Child index within bounds; qed");
            if child.is_leaf() {
                let index = child.index();
                if index < min_leaf_index {
                    min_leaf_index = index;
                }
                if index > max_leaf_index {
                    max_leaf_index = index;
                }
                leaf_indices.push(index);
            } else {
                node_locations.insert(child);
            }
        }

        // Move up to the parent location.
        location = parent;
    }

    (
        node_locations.into_iter().collect(),
        leaf_indices,
        (min_leaf_index, max_leaf_index),
    )
}

impl<const L: usize, const M: usize, C: CurveTreeConfig> LeafPathBuilder<L, M, C> {
    /// Create a new LeafPathBuilder
    pub fn new(leaf_index: LeafIndex, height: NodeLevel, block_number: BlockNumber) -> Self {
        let (node_locations, leaf_indices, leaf_range) =
            calculate_node_locations::<L>(leaf_index, height);
        Self {
            leaf_index,
            height,
            block_number,
            node_locations,
            nodes: BTreeMap::new(),
            leaves: BTreeMap::new(),
            leaf_range,
            leaf_indices,
            root: None,
        }
    }

    /// Get the list of node locations to query
    pub fn get_locations(&self) -> Vec<NodeLocation<L>> {
        self.node_locations.clone()
    }

    /// Get the leaf indices
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.leaf_indices.clone()
    }

    /// Get the min leaf index
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.leaf_range.0
    }

    /// Get the max leaf index
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.leaf_range.1
    }

    /// Set the root.
    pub fn set_root(&mut self, root: &[u8]) {
        self.root = Some(root.to_vec());
    }

    /// Set a leaf at the given index.
    pub fn set_leaf(&mut self, leaf_index: LeafIndex, leaf: Option<JsValue>) -> Result<(), Error> {
        if let Some(leaf) = leaf {
            let leaf = js_sys::Uint8Array::from(leaf).to_vec();
            let leaf = Decode::decode(&mut &leaf[..]).map_err(|e| {
                crate::Error::other(&format!("Failed to decode curve tree leaf: {}", e))
            })?;
            self.leaves.insert(leaf_index, leaf);
        } else {
            self.leaves.remove(&leaf_index);
        }
        Ok(())
    }

    /// Set a node at the given location index.
    pub fn set_node_at_index(
        &mut self,
        location_index: usize,
        node: Option<JsValue>,
    ) -> Result<(), Error> {
        if location_index > self.node_locations.len() {
            return Err(crate::Error::other(&format!(
                "Location index {} out of bounds (max {})",
                location_index,
                self.node_locations.len()
            )));
        }
        let location = self.node_locations[location_index];
        self.set_node(&location, node)
    }

    /// Set a node at the given location.
    pub fn set_node(
        &mut self,
        location: &NodeLocation<L>,
        node: Option<JsValue>,
    ) -> Result<(), Error> {
        if let Some(node) = node {
            let node = js_sys::Uint8Array::from(node).to_vec();
            let node = Decode::decode(&mut &node[..]).map_err(|e| {
                crate::Error::other(&format!("Failed to decode curve tree inner node: {}", e))
            })?;
            self.nodes.insert(location.clone(), node);
        } else {
            self.nodes.remove(location);
        }
        Ok(())
    }

    /// Set the leaves and nodes.
    pub fn set_leaves_and_nodes(
        &mut self,
        leaves: Vec<JsValue>,
        nodes: Vec<JsValue>,
    ) -> Result<(), Error> {
        for (idx, leaf) in leaves.into_iter().enumerate() {
            let leaf_index = self.leaf_indices[idx];
            self.set_leaf(leaf_index, Some(leaf))?;
        }
        for (idx, node) in nodes.into_iter().enumerate() {
            self.set_node_at_index(idx, Some(node))?;
        }
        Ok(())
    }
}

impl<const L: usize, const M: usize, C: CurveTreeConfig> CurveTreeBackend<L, M, C>
    for LeafPathBuilder<L, M, C>
{
    type Error = crate::Error;
    type Updater = DefaultCurveTreeUpdater<L, M, C>;

    fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Err(crate::Error::other(
            "LeafPathBuilder does not support new()",
        ))
    }

    fn parameters(&self) -> &SelRerandParameters<C::P0, C::P1> {
        C::parameters()
    }

    fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        Ok(self.block_number.into())
    }

    fn fetch_root(
        &self,
        _block_number: Option<BlockNumber>,
    ) -> Result<CompressedCurveTreeRoot<L, M, C>, Self::Error> {
        if let Some(root) = &self.root {
            let decoded_root = Decode::decode(&mut &root[..]).map_err(|e| {
                crate::Error::other(&format!("Failed to decode curve tree root: {}", e))
            })?;
            Ok(decoded_root)
        } else {
            Err(crate::Error::other(
                "Curve tree root not set in LeafPathBuilder",
            ))
        }
    }

    fn height(&self) -> NodeLevel {
        self.height
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
        _block_number: Option<BlockNumber>,
    ) -> Result<Option<CompressedLeafValue<C>>, Error> {
        Ok(self.leaves.get(&leaf_index).copied())
    }

    fn leaf_count(&self) -> LeafIndex {
        self.leaf_index
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<L>,
        _block_number: Option<BlockNumber>,
    ) -> Result<Option<CompressedInner<M, C>>, Error> {
        Ok(self.nodes.get(&location).cloned())
    }
}

type AssetLeafPathBuilderType = CurveTreeWithBackend<
    ASSET_TREE_L,
    ASSET_TREE_M,
    AssetTreeConfig,
    LeafPathBuilder<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>,
    Error,
>;

/// Asset leaf path builder.
#[wasm_bindgen]
#[derive(Clone)]
pub struct AssetLeafPathBuilder {
    pub(crate) tree: AssetLeafPathBuilderType,
}

#[wasm_bindgen]
impl AssetLeafPathBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(leaf_index: LeafIndex, height: NodeLevel, block_number: BlockNumber) -> Self {
        let backend = LeafPathBuilder::new(leaf_index, height, block_number);
        Self {
            tree: CurveTreeWithBackend::new_with_backend(backend)
                .expect("LeafPathBuilder backend; qed"),
        }
    }

    /// Return the `L` parameter of the tree.
    #[wasm_bindgen(js_name = getL)]
    pub fn get_l(&self) -> usize {
        ASSET_TREE_L
    }

    /// Return the `M` parameter of the tree.
    #[wasm_bindgen(js_name = getM)]
    pub fn get_m(&self) -> usize {
        ASSET_TREE_M
    }

    /// Get the list of node locations to query
    #[wasm_bindgen(js_name = getNodeLocations)]
    pub fn get_node_locations(&self) -> Vec<Uint8Array> {
        self.tree
            .backend
            .node_locations
            .iter()
            .map(|loc| loc.encode().as_slice().into())
            .collect()
    }

    /// Get the leaf indices
    #[wasm_bindgen(js_name = getLeafIndices)]
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.tree.backend.leaf_indices.clone()
    }

    /// Get the min leaf index
    #[wasm_bindgen(js_name = getMinLeafIndex)]
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_min_leaf_index()
    }

    /// Get the max leaf index
    #[wasm_bindgen(js_name = getMaxLeafIndex)]
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_max_leaf_index()
    }

    /// Set the root.
    #[wasm_bindgen(js_name = setRoot)]
    pub fn set_root(&mut self, root: &[u8]) {
        self.tree.backend.set_root(root);
    }

    /// Set a leaf at the given index.
    #[wasm_bindgen(js_name = setLeaf)]
    pub fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        leaf: Option<JsValue>,
    ) -> Result<(), JsValue> {
        self.tree
            .backend
            .set_leaf(leaf_index, leaf)
            .map_err(|e| JsValue::from_str(&format!("Failed to set leaf: {}", e)))
    }

    /// Set a node at the given location index.
    #[wasm_bindgen(js_name = setNodeAtIndex)]
    pub fn set_node_at_index(
        &mut self,
        location_index: usize,
        node: Option<JsValue>,
    ) -> Result<(), JsValue> {
        self.tree
            .backend
            .set_node_at_index(location_index, node)
            .map_err(|e| JsValue::from_str(&format!("Failed to set node: {}", e)))
    }

    /// Build the leaf path
    #[wasm_bindgen(js_name = buildLeafPath)]
    pub fn build_leaf_path(&mut self) -> Result<AssetLeafPath, JsValue> {
        let path = self
            .tree
            .get_path_to_leaf(self.tree.backend.leaf_index, 0, None)
            .map_err(|e| JsValue::from_str(&format!("Failed to build asset leaf path: {}", e)))?;

        Ok(AssetLeafPath {
            path: WrappedCanonical::wrap(&path).map_err(|e| {
                JsValue::from_str(&format!("Failed to wrap asset leaf path: {}", e))
            })?,
        })
    }

    /// Build the leaf path with root.
    #[wasm_bindgen(js_name = buildLeafPathWithRoot)]
    pub fn build_leaf_path_with_root(&mut self) -> Result<AssetLeafPathAndRoot, JsValue> {
        let path = self
            .tree
            .get_path_and_root(self.tree.backend.leaf_index, None)
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to build asset leaf path and root: {}", e))
            })?;

        Ok(AssetLeafPathAndRoot { path })
    }
}

type AccountLeafPathBuilderType = CurveTreeWithBackend<
    ACCOUNT_TREE_L,
    ACCOUNT_TREE_M,
    AccountTreeConfig,
    LeafPathBuilder<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>,
    Error,
>;

/// Account leaf path builder.
#[wasm_bindgen]
#[derive(Clone)]
pub struct AccountLeafPathBuilder {
    pub(crate) tree: AccountLeafPathBuilderType,
}

#[wasm_bindgen]
impl AccountLeafPathBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(leaf_index: LeafIndex, height: NodeLevel, block_number: BlockNumber) -> Self {
        let backend = LeafPathBuilder::new(leaf_index, height, block_number);
        Self {
            tree: CurveTreeWithBackend::new_with_backend(backend)
                .expect("LeafPathBuilder backend; qed"),
        }
    }

    /// Return the `L` parameter of the tree.
    #[wasm_bindgen(js_name = getL)]
    pub fn get_l(&self) -> usize {
        ACCOUNT_TREE_L
    }

    /// Return the `M` parameter of the tree.
    #[wasm_bindgen(js_name = getM)]
    pub fn get_m(&self) -> usize {
        ACCOUNT_TREE_M
    }

    /// Get the list of node locations to query
    #[wasm_bindgen(js_name = getNodeLocations)]
    pub fn get_node_locations(&self) -> Vec<Uint8Array> {
        self.tree
            .backend
            .node_locations
            .iter()
            .map(|loc| loc.encode().as_slice().into())
            .collect()
    }

    /// Get the leaf indices
    #[wasm_bindgen(js_name = getLeafIndices)]
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.tree.backend.leaf_indices.clone()
    }

    /// Get the min leaf index
    #[wasm_bindgen(js_name = getMinLeafIndex)]
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_min_leaf_index()
    }

    /// Get the max leaf index
    #[wasm_bindgen(js_name = getMaxLeafIndex)]
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_max_leaf_index()
    }

    /// Set the root.
    #[wasm_bindgen(js_name = setRoot)]
    pub fn set_root(&mut self, root: &[u8]) {
        self.tree.backend.set_root(root);
    }

    /// Set a leaf at the given index.
    #[wasm_bindgen(js_name = setLeaf)]
    pub fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        leaf: Option<JsValue>,
    ) -> Result<(), JsValue> {
        self.tree
            .backend
            .set_leaf(leaf_index, leaf)
            .map_err(|e| JsValue::from_str(&format!("Failed to set leaf: {}", e)))
    }

    /// Set a node at the given location index.
    #[wasm_bindgen(js_name = setNodeAtIndex)]
    pub fn set_node_at_index(
        &mut self,
        location_index: usize,
        node: Option<JsValue>,
    ) -> Result<(), JsValue> {
        self.tree
            .backend
            .set_node_at_index(location_index, node)
            .map_err(|e| JsValue::from_str(&format!("Failed to set node: {}", e)))
    }

    /// Build the leaf path with root.
    #[wasm_bindgen(js_name = buildLeafPathWithRoot)]
    pub fn build_leaf_path_with_root(&mut self) -> Result<AccountLeafPathAndRoot, JsValue> {
        let path = self
            .tree
            .get_path_and_root(self.tree.backend.leaf_index, None)
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to build account leaf path and root: {}",
                    e
                ))
            })?;

        Ok(AccountLeafPathAndRoot { path })
    }
}
