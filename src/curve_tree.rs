use std::collections::{BTreeMap, BTreeSet};

use codec::{Decode, Encode};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use polymesh_dart::{
    curve_tree::{
        AccountTreeConfig, AssetTreeConfig, CompressedCurveTreeRoot, CompressedInner,
        CompressedLeafValue, CurveTreeBackend, CurveTreeConfig, CurveTreeLookup, CurveTreePath,
        CurveTreeWithBackend, DefaultCurveTreeUpdater, FeeAccountTreeConfig, LeafPathAndRoot,
        NodeLocation, SelRerandProofParametersNew,
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
///
/// Contains both the curve tree path from a fee account leaf to the root and the root value itself
/// at a specific block number. Used for generating zero-knowledge proofs about fee account states.
#[wasm_bindgen]
pub struct FeeAccountLeafPathAndRoot {
    pub(crate) path: NativeFeeAccountLeafPathAndRoot,
}

#[wasm_bindgen]
impl FeeAccountLeafPathAndRoot {
    /// Exports the fee account leaf path and root as a SCALE-encoded byte array.
    ///
    /// This is useful for storing or transmitting the path and root in a compact binary format.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Example
    /// ```javascript
    /// const feeAccountCurveTree = await client.getFeeAccountCurveTree();
    /// const pathAndRoot = await feeAccountCurveTree.getLeafPathAndRoot(leafIndex);
    /// const bytes = pathAndRoot.toBytes();
    /// // Store or transmit bytes
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Imports a fee account leaf path and root from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Returns
    /// A `FeeAccountLeafPathAndRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the bytes are not a valid SCALE-encoded fee account leaf path and root.
    ///
    /// # Example
    /// ```javascript
    /// const pathAndRoot = FeeAccountLeafPathAndRoot.fromBytes(bytes);
    /// ```
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
///
/// Contains both the curve tree path from an account leaf to the root and the root value itself
/// at a specific block number. Used for generating zero-knowledge proofs about account states
/// (e.g., proving balance sufficiency during settlement affirmations).
#[wasm_bindgen]
pub struct AccountLeafPathAndRoot {
    pub(crate) path: NativeAccountLeafPathAndRoot,
}

#[wasm_bindgen]
impl AccountLeafPathAndRoot {
    /// Exports the account leaf path and root as a SCALE-encoded byte array.
    ///
    /// This is useful for storing or transmitting the path and root in a compact binary format.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Example
    /// ```javascript
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const pathAndRoot = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    /// const bytes = pathAndRoot.toBytes();
    /// // Store or transmit bytes
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Imports an account leaf path and root from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Returns
    /// A `FeeAccountLeafPathAndRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the bytes are not a valid SCALE-encoded account leaf path and root.
    ///
    /// # Example
    /// ```javascript
    /// const pathAndRoot = AccountLeafPathAndRoot.fromBytes(bytes);
    /// ```
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

    /// Gets the block number at which this root was generated.
    ///
    /// The block number indicates at which blockchain state the curve tree root was calculated.
    /// This is important for ensuring proofs are verified against the correct historical state.
    ///
    /// # Returns
    /// The block number as a `u32`.
    ///
    /// # Errors
    /// * Throws an error if the block number cannot be extracted from the path.
    ///
    /// # Example
    /// ```javascript
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const pathAndRoot = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    /// const blockNumber = pathAndRoot.getBlockNumber();
    /// console.log(`Root calculated at block ${blockNumber}`);
    /// ```
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> Result<u32, JsValue> {
        self.path
            .get_block_number()
            .map_err(|e| JsValue::from_str(&format!("Failed to get block number: {}", e)))
    }
}

/// Asset leaf path and root.
///
/// Contains both the curve tree path from an asset leaf to the root and the root value itself
/// at a specific block number. Assets are stored in their own curve tree separate from accounts.
/// This structure is used when building settlement proofs to prove asset states.
#[wasm_bindgen]
pub struct AssetLeafPathAndRoot {
    pub(crate) path: NativeAssetLeafPathAndRoot,
}

#[wasm_bindgen]
impl AssetLeafPathAndRoot {
    /// Exports the asset leaf path and root as a SCALE-encoded byte array.
    ///
    /// This is useful for storing or transmitting the path and root in a compact binary format.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Example
    /// ```javascript
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const pathAndRoot = await assetCurveTree.getLeafPathAndRoot(assetState.leafIndex());
    /// const bytes = pathAndRoot.toBytes();
    /// // Store or transmit bytes
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Imports an asset leaf path and root from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing the SCALE-encoded path and root.
    ///
    /// # Returns
    /// An `AssetLeafPathAndRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the bytes are not a valid SCALE-encoded asset leaf path and root.
    ///
    /// # Example
    /// ```javascript
    /// const pathAndRoot = AssetLeafPathAndRoot.fromBytes(bytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetLeafPathAndRoot, JsValue> {
        let path = Decode::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode asset leaf path and root: {}", e))
        })?;
        Ok(AssetLeafPathAndRoot { path })
    }

    /// Extracts the asset tree root from the path and root.
    ///
    /// The root represents the commitment to all asset states in the tree at a specific block.
    ///
    /// # Returns
    /// An `AssetTreeRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the root cannot be extracted from the path.
    ///
    /// # Example
    /// ```javascript
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const pathAndRoot = await assetCurveTree.getLeafPathAndRoot(assetState.leafIndex());
    /// const root = pathAndRoot.getRoot();
    /// ```
    #[wasm_bindgen(js_name = getRoot)]
    pub fn get_root(&self) -> Result<AssetTreeRoot, JsValue> {
        let root = self
            .path
            .root()
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset tree root: {}", e)))?;
        Ok(AssetTreeRoot { root })
    }

    /// Gets the block number at which this root was generated.
    ///
    /// The block number indicates at which blockchain state the curve tree root was calculated.
    /// This is critical for settlement proofs as they must reference a specific block state.
    ///
    /// # Returns
    /// The block number as a `u32`.
    ///
    /// # Errors
    /// * Throws an error if the block number cannot be extracted from the path.
    ///
    /// # Example
    /// ```javascript
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const pathAndRoot = await assetCurveTree.getLeafPathAndRoot(assetState.leafIndex());
    /// const blockNumber = pathAndRoot.getBlockNumber();
    /// console.log(`Asset root at block ${blockNumber}`);
    /// ```
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> Result<u32, JsValue> {
        self.path
            .get_block_number()
            .map_err(|e| JsValue::from_str(&format!("Failed to get block number: {}", e)))
    }
}

/// Asset tree root.
///
/// Represents the root commitment of the asset curve tree at a specific point in time.
/// This root is used in settlement proofs to verify that asset states are valid.
#[wasm_bindgen]
pub struct AssetTreeRoot {
    pub(crate) root: NativeAssetTreeRoot,
}

#[wasm_bindgen]
impl AssetTreeRoot {
    /// Exports the asset tree root as a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded root.
    ///
    /// # Example
    /// ```javascript
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const pathAndRoot = await assetCurveTree.getLeafPathAndRoot(assetState.leafIndex());
    /// const root = pathAndRoot.getRoot();
    /// const bytes = root.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.root.encode()
    }

    /// Imports an asset tree root from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing the SCALE-encoded root.
    ///
    /// # Returns
    /// An `AssetTreeRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the bytes are not a valid SCALE-encoded asset tree root.
    ///
    /// # Example
    /// ```javascript
    /// const root = AssetTreeRoot.fromBytes(bytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetTreeRoot, JsValue> {
        let root = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset tree root: {}", e)))?;
        Ok(AssetTreeRoot { root })
    }
}

/// Asset leaf path.
///
/// Contains the curve tree path from an asset leaf to the root (without the root value itself).
/// Used when you only need the path structure without the specific root commitment.
#[wasm_bindgen]
pub struct AssetLeafPath {
    pub(crate) path: NativeAssetLeafPath,
}

#[wasm_bindgen]
impl AssetLeafPath {
    /// Exports the asset leaf path as a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded path.
    ///
    /// # Example
    /// ```javascript
    /// const assetLeafPathBuilder = new AssetLeafPathBuilder(leafIndex, height, blockNumber);
    /// // ... set leaves and nodes ...
    /// const path = assetLeafPathBuilder.buildLeafPath();
    /// const bytes = path.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.path.encode()
    }

    /// Imports an asset leaf path from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing the SCALE-encoded path.
    ///
    /// # Returns
    /// An `AssetLeafPath` instance.
    ///
    /// # Errors
    /// * Throws an error if the bytes are not a valid SCALE-encoded asset leaf path.
    ///
    /// # Example
    /// ```javascript
    /// const path = AssetLeafPath.fromBytes(bytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetLeafPath, JsValue> {
        let path = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset leaf path: {}", e)))?;
        Ok(AssetLeafPath { path })
    }
}

/// Generic leaf path builder for curve trees.
///
/// A generic data structure that enables incremental construction of curve tree paths by querying
/// on-chain data. This is an internal implementation detail used by `AssetLeafPathBuilder`,
/// `AccountLeafPathBuilder`, and `FeeAccountLeafPathBuilder` to provide type-safe, specialized
/// path builders for each tree type.
///
/// # Description
/// `LeafPathBuilder` is a generic helper that manages the collection of tree data (leaves, inner nodes,
/// and the root) needed to construct a complete path from a target leaf to the root. It automatically
/// calculates which tree nodes and leaves are necessary for the path based on the target leaf index
/// and tree height, then stores them in memory for later retrieval and path construction.
///
/// # Type Parameters
/// * `L` - The branching factor (arity) of the curve tree. Determines how many children each node can have.
///   For example, `ASSET_TREE_L = 4` means each node has up to 4 children.
/// * `M` - The compression parameter for inner nodes. Specifies the maximum number of children
///   that can be stored in a compressed inner node structure.
/// * `C` - The curve tree configuration (e.g., `AssetTreeConfig`, `AccountTreeConfig`).
///   Determines the cryptographic parameters and tree structure rules.
///
/// # Fields
/// * `leaf_index` - The index of the target leaf for which the path is being built.
/// * `height` - The height of the tree (number of levels from leaf to root).
/// * `block_number` - The blockchain block number at which the tree state should be captured.
/// * `node_locations` - A vector of all inner node locations that need to be queried and populated.
/// * `nodes` - A mapping from node locations to their compressed inner node values.
/// * `leaves` - A mapping from leaf indices to their compressed leaf values.
/// * `leaf_range` - A tuple `(min_index, max_index)` representing the range of leaf indices required.
/// * `leaf_indices` - A vector of all leaf indices that need to be queried and populated.
/// * `root` - Optional storage for the tree root. Must be set before building a path with root.
///
/// # Workflow
/// The typical workflow for using `LeafPathBuilder` (or its type-specialized variants) is:
/// 1. Create a new builder with target leaf index, tree height, and block number
/// 2. Query `node_locations` and `leaf_indices` to know what data to fetch from the blockchain
/// 3. Fetch inner nodes from storage and populate them using `set_node()` or `set_node_at_index()`
/// 4. Fetch leaves from storage and populate them using `set_leaf()`
/// 5. Fetch and set the tree root using `set_root()`
/// 6. Call the appropriate build method to construct the final path
///
/// # Internal Implementation Note
/// This is primarily used as a `CurveTreeBackend` implementation, which allows the curve tree
/// logic to retrieve stored leaves and nodes during path construction. It should not be used
/// directly from user code; instead, use the specialized `AssetLeafPathBuilder`,
/// `AccountLeafPathBuilder`, or `FeeAccountLeafPathBuilder` types.
///
/// # Example (Rust)
/// ```rust, ignore
/// use polymesh_dart::BlockNumber;
/// // Create a new builder for a leaf at index 42 in a tree of height 4 at block 1000
/// let mut builder = LeafPathBuilder::new(42, 4, BlockNumber(1000));
///
/// // Get the node locations to query
/// let node_locations = builder.get_locations();
/// // Query blockchain storage for each location and populate
/// for location in node_locations {
///     // fetch node from blockchain...
///     builder.set_node(&location, Some(node_bytes))?;
/// }
///
/// // Get leaf indices to query
/// let leaf_indices = builder.get_leaf_indices();
/// // Query blockchain storage for each leaf
/// for leaf_idx in leaf_indices {
///     // fetch leaf from blockchain...
///     builder.set_leaf(leaf_idx, Some(leaf_bytes))?;
/// }
///
/// // Set the root
/// builder.set_root(&root_bytes);
/// ```
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
    /// Creates a new `LeafPathBuilder` instance initialized with the given parameters.
    ///
    /// This method automatically calculates which tree nodes and leaves are required to construct
    /// a path from the target leaf to the root, and sets up the internal data structures to store them.
    ///
    /// # Arguments
    /// * `leaf_index` - The `LeafIndex` of the target leaf in the tree. This is the leaf for which
    ///   the path will be constructed. Typically obtained from an asset or account state.
    /// * `height` - The `NodeLevel` representing the height of the tree (number of levels from leaf to root).
    ///   For example, `4` for a 4-level tree.
    /// * `block_number` - The `BlockNumber` at which the tree state should be captured. All queried
    ///   nodes and leaves should be from this specific block.
    ///
    /// # Returns
    /// A new `LeafPathBuilder` instance with:
    /// - Automatically calculated node locations that need to be queried
    /// - Automatically calculated leaf indices that need to be queried
    /// - Empty storage for nodes and leaves (must be populated via `set_node()` and `set_leaf()`)
    /// - Empty root storage (must be set via `set_root()`)
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let builder = LeafPathBuilder::new(
    ///     LeafIndex(42),      // target leaf
    ///     NodeLevel(4),       // tree height
    ///     BlockNumber(1000)   // block number
    /// );
    /// let required_nodes = builder.get_locations();
    /// let required_leaves = builder.get_leaf_indices();
    /// ```
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

    /// Retrieves the list of inner node locations that must be queried from the blockchain.
    ///
    /// These locations represent all the inner nodes on the path from the target leaf to the root,
    /// including all necessary sibling nodes. This list should be used to query the blockchain's
    /// confidentialAssets storage for inner nodes.
    ///
    /// # Returns
    /// A `Vec<NodeLocation<L>>` containing all the node locations needed. Each location can be
    /// SCALE-encoded and used as a key in on-chain storage queries.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let locations = builder.get_locations();
    /// // For each location, query: api.query.confidentialAssets.curveTreeInnerNodes(location)
    /// ```
    pub fn get_locations(&self) -> Vec<NodeLocation<L>> {
        self.node_locations.clone()
    }

    /// Retrieves the list of leaf indices that must be queried from the blockchain.
    ///
    /// These are all the sibling leaves along the path to the target leaf, plus the target leaf itself.
    /// All these leaves must be fetched from the blockchain and populated using `set_leaf()`.
    ///
    /// # Returns
    /// A `Vec<LeafIndex>` containing all the leaf indices needed. These indices can be used to
    /// query the blockchain's confidentialAssets storage for leaf values.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let leaf_indices = builder.get_leaf_indices();
    /// // For each index, query: api.query.confidentialAssets.curveTreeLeaves(index, block_number)
    /// ```
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.leaf_indices.clone()
    }

    /// Retrieves the minimum leaf index in the required range.
    ///
    /// Combined with `get_max_leaf_index()`, this defines a contiguous range of leaf indices
    /// that need to be fetched. This is useful for efficient batch queries of consecutive leaves.
    ///
    /// # Returns
    /// A `LeafIndex` representing the inclusive lower bound of the leaf range.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let min = builder.get_min_leaf_index();
    /// let max = builder.get_max_leaf_index();
    /// // Query all leaves in range [min, max)
    /// ```
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.leaf_range.0
    }

    /// Retrieves the maximum leaf index in the required range.
    ///
    /// Combined with `get_min_leaf_index()`, this defines a contiguous range of leaf indices
    /// that need to be fetched. The range is [min, max) (exclusive on the upper bound).
    ///
    /// # Returns
    /// A `LeafIndex` representing the exclusive upper bound of the leaf range.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let min = builder.get_min_leaf_index();
    /// let max = builder.get_max_leaf_index();
    /// // Query all leaves in range [min, max)
    /// for i in min.0..max.0 {
    ///     // fetch and set leaf at index i
    /// }
    /// ```
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.leaf_range.1
    }

    /// Stores the tree root value in the builder.
    ///
    /// The root must be set before building a path that includes the root. This is typically the
    /// value returned by querying the blockchain's `confidentialAssets.curveTreeRoots` storage
    /// for the specified block number.
    ///
    /// # Arguments
    /// * `root` - A byte slice containing the SCALE-encoded tree root value retrieved from the blockchain.
    ///   This should be the root at the same block number specified during builder construction.
    ///
    /// # Side Effects
    /// Stores an internal clone of the provided root bytes for later use during path construction.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let mut builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let root_bytes = /* fetch from blockchain */;
    /// builder.set_root(&root_bytes);
    /// ```
    pub fn set_root(&mut self, root: &[u8]) {
        self.root = Some(root.to_vec());
    }

    /// Stores a leaf value at the specified index, or removes it if `None` is provided.
    ///
    /// This method decodes the provided SCALE-encoded leaf bytes and stores it internally.
    /// All leaves returned by `get_leaf_indices()` must be set before building a path.
    ///
    /// # Arguments
    /// * `leaf_index` - The `LeafIndex` at which to store the leaf. Should be one of the indices
    ///   returned by `get_leaf_indices()`.
    /// * `leaf` - An `Option<JsValue>` containing:
    ///   - `Some(js_value)` - A SCALE-encoded leaf value to store (will be decoded internally)
    ///   - `None` - To remove a previously stored leaf at this index
    ///
    /// # Returns
    /// `Ok(())` if the leaf was successfully decoded and stored, or removed.
    ///
    /// # Errors
    /// * Returns an error if the provided leaf bytes cannot be decoded as a valid `CompressedLeafValue<C>`.
    ///   Error message will include details about the decoding failure.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let mut builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let leaf_indices = builder.get_leaf_indices();
    /// for &idx in &leaf_indices {
    ///     let leaf_bytes = /* fetch from blockchain */;
    ///     // Create a JsValue from the bytes (in actual Wasm code)
    ///     builder.set_leaf(idx, Some(leaf_js_value))?;
    /// }
    /// ```
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

    /// Stores an inner node at the specified location index, or removes it if `None` is provided.
    ///
    /// The location index corresponds to the position in the vector returned by `get_locations()`.
    /// This method decodes the provided SCALE-encoded node bytes and stores it internally.
    ///
    /// # Arguments
    /// * `location_index` - A `usize` representing the position in the node locations vector.
    ///   Must be less than the length of the vector returned by `get_locations()`.
    /// * `node` - An `Option<JsValue>` containing:
    ///   - `Some(js_value)` - A SCALE-encoded inner node to store (will be decoded internally)
    ///   - `None` - To remove a previously stored node at this location index
    ///
    /// # Returns
    /// `Ok(())` if the node was successfully decoded and stored, or removed.
    ///
    /// # Errors
    /// * `Error` with message "Location index X out of bounds (max Y)" if the index exceeds the
    ///   size of the node locations vector.
    /// * `Error` if the provided node bytes cannot be decoded as a valid `CompressedInner<M, C>`.
    ///   Error message will include details about the decoding failure.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let mut builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let locations = builder.get_locations();
    /// for (idx, location) in locations.iter().enumerate() {
    ///     let node_bytes = /* fetch from blockchain using location */;
    ///     // Create a JsValue from the bytes (in actual Wasm code)
    ///     builder.set_node_at_index(idx, Some(node_js_value))?;
    /// }
    /// ```
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

    /// Stores an inner node at the specified location, or removes it if `None` is provided.
    ///
    /// This is an alternative to `set_node_at_index()` when you have the `NodeLocation` directly
    /// rather than its index. This method decodes the provided SCALE-encoded node bytes and stores it.
    ///
    /// # Arguments
    /// * `location` - A reference to a `NodeLocation<L>` where the node should be stored.
    /// * `node` - An `Option<JsValue>` containing:
    ///   - `Some(js_value)` - A SCALE-encoded inner node to store (will be decoded internally)
    ///   - `None` - To remove a previously stored node at this location
    ///
    /// # Returns
    /// `Ok(())` if the node was successfully decoded and stored, or removed.
    ///
    /// # Errors
    /// * `Error` if the provided node bytes cannot be decoded as a valid `CompressedInner<M, C>`.
    ///   Error message will include details about the decoding failure.
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let mut builder = LeafPathBuilder::new(leaf_index, height, block_number);
    /// let locations = builder.get_locations();
    /// for location in locations {
    ///     let node_bytes = /* fetch from blockchain using location */;
    ///     // Create a JsValue from the bytes (in actual Wasm code)
    ///     builder.set_node(&location, Some(node_js_value))?;
    /// }
    /// ```
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

    /// Batch stores multiple leaves and nodes at once.
    ///
    /// This is a convenience method for populating the builder with all required leaves and nodes
    /// in a single call. The leaves and nodes are expected to be in the same order as returned
    /// by `get_leaf_indices()` and `get_locations()` respectively.
    ///
    /// # Arguments
    /// * `leaves` - A `Vec<JsValue>` containing SCALE-encoded leaf values, in the same order as
    ///   `get_leaf_indices()`. Each value will be decoded and stored at the corresponding index.
    /// * `nodes` - A `Vec<JsValue>` containing SCALE-encoded inner nodes, in the same order as
    ///   `get_locations()`. Each value will be decoded and stored at the corresponding location.
    ///
    /// # Returns
    /// `Ok(())` if all leaves and nodes were successfully decoded and stored.
    ///
    /// # Errors
    /// * `Error` if any leaf or node cannot be decoded.
    /// * `Error` if a location index is out of bounds (if the nodes vector is longer than expected).
    /// Errors are returned on the first failure encountered during iteration.
    ///
    /// # Panics
    /// This method will panic if:
    /// - The `leaves` vector length does not match `get_leaf_indices().len()`
    /// - The `nodes` vector length does not match `get_locations().len()`
    ///
    /// # Example (Rust)
    /// ```rust, ignore
    /// let mut builder = LeafPathBuilder::new(leaf_index, height, block_number);
    ///
    /// // Fetch all leaves
    /// let leaf_indices = builder.get_leaf_indices();
    /// let mut leaves = Vec::new();
    /// for &idx in &leaf_indices {
    ///     leaves.push(/* fetch and encode leaf */);
    /// }
    ///
    /// // Fetch all nodes
    /// let locations = builder.get_locations();
    /// let mut nodes = Vec::new();
    /// for location in &locations {
    ///     nodes.push(/* fetch and encode node */);
    /// }
    ///
    /// // Set them all at once
    /// builder.set_leaves_and_nodes(leaves, nodes)?;
    /// ```
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

    fn parameters(
        &self,
    ) -> &SelRerandProofParametersNew<C::P0, C::P1, C::DLogParams0, C::DLogParams1> {
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
///
/// A utility for incrementally building curve tree paths for assets in the asset curve tree.
/// This builder helps you construct paths by querying on-chain data (leaves, inner nodes, and roots)
/// and assembling them into a complete path structure.
///
/// # Workflow
/// 1. Create a new builder with the target leaf index, tree height, and block number
/// 2. Get the list of node locations needed from `getNodeLocations()`
/// 3. Query the blockchain for inner nodes at those locations
/// 4. Get the range of leaf indices needed from `getMinLeafIndex()` / `getMaxLeafIndex()`
/// 5. Query the blockchain for those leaves
/// 6. Query the blockchain for the tree root at the block number
/// 7. Set all the data using `setLeaf()`, `setNodeAtIndex()`, and `setRoot()`
/// 8. Build the final path with `buildLeafPath()` or `buildLeafPathWithRoot()`
///
/// # Example
/// ```javascript
/// const assetCurveTree = await client.getAssetCurveTree();
/// const blockNumber = await assetCurveTree.getLastBlockNumber();
/// const leafIndex = assetState.leafIndex();
///
/// // Create the builder
/// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
///
/// // Query and set leaves
/// const minLeaf = builder.getMinLeafIndex();
/// const maxLeaf = builder.getMaxLeafIndex();
/// for (let i = minLeaf; i < maxLeaf; i++) {
///   const leaf = await client.getAssetLeaf(i, blockNumber);
///   builder.setLeaf(i, leaf);
/// }
///
/// // Query and set inner nodes
/// const nodeLocations = builder.getNodeLocations();
/// for (let i = 0; i < nodeLocations.length; i++) {
///   const node = await client.getAssetInnerNode(nodeLocations[i], blockNumber);
///   builder.setNodeAtIndex(i, node);
/// }
///
/// // Query and set root
/// const root = await client.getAssetTreeRoot(blockNumber);
/// builder.setRoot(root);
///
/// // Build the path
/// const pathAndRoot = builder.buildLeafPathWithRoot();
/// ```
#[wasm_bindgen]
#[derive(Clone)]
pub struct AssetLeafPathBuilder {
    pub(crate) tree: AssetLeafPathBuilderType,
}

#[wasm_bindgen]
impl AssetLeafPathBuilder {
    /// Creates a new asset leaf path builder.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the tree (typically from `assetState.leafIndex()`)
    /// * `height` - The height of the tree (typically 4 for asset trees)
    /// * `block_number` - The block number at which to build the path
    ///
    /// # Returns
    /// A new `AssetLeafPathBuilder` instance ready to collect tree data.
    ///
    /// # Example
    /// ```javascript
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    /// const leafIndex = assetState.leafIndex();
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(leaf_index: LeafIndex, height: NodeLevel, block_number: BlockNumber) -> Self {
        let backend = LeafPathBuilder::new(leaf_index, height, block_number);
        Self {
            tree: CurveTreeWithBackend::new_with_backend(backend)
                .expect("LeafPathBuilder backend; qed"),
        }
    }

    /// Returns the `L` parameter of the asset tree.
    ///
    /// This represents the branching factor (arity) of the tree - how many children each node has.
    ///
    /// # Returns
    /// The tree arity as a number (typically 4 for asset trees).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// console.log(`Tree arity: ${builder.getL()}`); // 4
    /// ```
    #[wasm_bindgen(js_name = getL)]
    pub fn get_l(&self) -> usize {
        ASSET_TREE_L
    }

    /// Returns the `M` parameter of the asset tree.
    ///
    /// This represents the maximum number of children stored in each compressed inner node.
    ///
    /// # Returns
    /// The compression parameter as a number.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// console.log(`Compression parameter: ${builder.getM()}`);
    /// ```
    #[wasm_bindgen(js_name = getM)]
    pub fn get_m(&self) -> usize {
        ASSET_TREE_M
    }

    /// Gets the list of inner node locations that need to be queried from the blockchain.
    ///
    /// Returns an array of SCALE-encoded node locations. These should be used to query
    /// the on-chain storage for inner nodes.
    ///
    /// # Returns
    /// An array of `Uint8Array` values, each representing a SCALE-encoded node location.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAssetInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getNodeLocations)]
    pub fn get_node_locations(&self) -> Vec<Uint8Array> {
        self.tree
            .backend
            .node_locations
            .iter()
            .map(|loc| loc.encode().as_slice().into())
            .collect()
    }

    /// Gets the list of leaf indices that need to be queried from the blockchain.
    ///
    /// Returns all sibling leaf indices along the path to the target leaf.
    ///
    /// # Returns
    /// An array of leaf indices (as numbers).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const leafIndices = builder.getLeafIndices();
    /// for (const index of leafIndices) {
    ///   const leaf = await client.getAssetLeaf(index, blockNumber);
    ///   builder.setLeaf(index, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getLeafIndices)]
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.tree.backend.leaf_indices.clone()
    }

    /// Gets the minimum leaf index that needs to be queried.
    ///
    /// Combined with `getMaxLeafIndex()`, this defines a range of leaves to query.
    ///
    /// # Returns
    /// The minimum leaf index as a number.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAssetLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getMinLeafIndex)]
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_min_leaf_index()
    }

    /// Gets the maximum leaf index that needs to be queried.
    ///
    /// Combined with `getMinLeafIndex()`, this defines a range of leaves to query.
    ///
    /// # Returns
    /// The maximum leaf index as a number (exclusive - use `i < maxLeaf` in loops).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAssetLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getMaxLeafIndex)]
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_max_leaf_index()
    }

    /// Sets the tree root value.
    ///
    /// # Arguments
    /// * `root` - A `Uint8Array` containing the SCALE-encoded tree root
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const root = await client.getAssetTreeRoot(blockNumber);
    /// builder.setRoot(root);
    /// ```
    #[wasm_bindgen(js_name = setRoot)]
    pub fn set_root(&mut self, root: &[u8]) {
        self.tree.backend.set_root(root);
    }

    /// Sets a leaf value at the specified index.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the leaf in the tree
    /// * `leaf` - A `Uint8Array` containing the SCALE-encoded leaf value, or `null`/`undefined` to remove
    ///
    /// # Errors
    /// * Throws an error if the leaf data cannot be decoded.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const leaf = await client.getAssetLeaf(0, blockNumber);
    /// builder.setLeaf(0, leaf);
    /// ```
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

    /// Sets an inner node at the specified location index.
    ///
    /// The location index corresponds to the position in the array returned by `getNodeLocations()`.
    ///
    /// # Arguments
    /// * `location_index` - The index in the node locations array
    /// * `node` - A `Uint8Array` containing the SCALE-encoded inner node, or `null`/`undefined` to remove
    ///
    /// # Errors
    /// * Throws an error if the location index is out of bounds.
    /// * Throws an error if the node data cannot be decoded.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAssetInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    /// ```
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

    /// Builds the asset leaf path (without the root).
    ///
    /// Constructs the curve tree path from the target leaf to the root using the leaves and nodes
    /// that have been set. The root itself is not included in the result.
    ///
    /// # Returns
    /// An `AssetLeafPath` instance containing the curve tree path.
    ///
    /// # Errors
    /// * Throws an error if required leaves or nodes have not been set.
    /// * Throws an error if the path cannot be constructed.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    /// // ... set all leaves and nodes ...
    /// const path = builder.buildLeafPath();
    /// ```
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

    /// Builds the asset leaf path with the root included.
    ///
    /// Constructs the complete curve tree path from the target leaf to the root, including the root value.
    /// This is the most common method used as proofs typically require both the path and the root.
    ///
    /// # Returns
    /// An `AssetLeafPathAndRoot` instance containing both the curve tree path and the root.
    ///
    /// # Errors
    /// * Throws an error if required leaves, nodes, or root have not been set.
    /// * Throws an error if the path cannot be constructed.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AssetLeafPathBuilder(leafIndex, 4, blockNumber);
    ///
    /// // Set all leaves
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAssetLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    ///
    /// // Set all inner nodes
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAssetInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    ///
    /// // Set the root
    /// const root = await client.getAssetTreeRoot(blockNumber);
    /// builder.setRoot(root);
    ///
    /// // Build the complete path with root
    /// const pathAndRoot = builder.buildLeafPathWithRoot();
    /// ```
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
///
/// A utility for incrementally building curve tree paths for accounts in the account curve tree.
/// This builder helps you construct paths by querying on-chain data (leaves, inner nodes, and roots)
/// and assembling them into a complete path structure.
///
/// The workflow is identical to `AssetLeafPathBuilder` but operates on the account tree instead of the asset tree.
/// Account paths are used when generating proofs related to account states (balance commitments, etc.).
///
/// # Workflow
/// 1. Create a new builder with the target leaf index, tree height, and block number
/// 2. Get the list of node locations needed from `getNodeLocations()`
/// 3. Query the blockchain for inner nodes at those locations
/// 4. Get the range of leaf indices needed from `getMinLeafIndex()` / `getMaxLeafIndex()`
/// 5. Query the blockchain for those leaves
/// 6. Query the blockchain for the tree root at the block number
/// 7. Set all the data using `setLeaf()`, `setNodeAtIndex()`, and `setRoot()`
/// 8. Build the final path with `buildLeafPathWithRoot()`
///
/// # Example
/// ```javascript
/// const accountCurveTree = await client.getAccountCurveTree();
/// const blockNumber = await accountCurveTree.getLastBlockNumber();
/// const leafIndex = accountState.leafIndex();
///
/// // Create the builder
/// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
///
/// // Query and set leaves
/// const minLeaf = builder.getMinLeafIndex();
/// const maxLeaf = builder.getMaxLeafIndex();
/// for (let i = minLeaf; i < maxLeaf; i++) {
///   const leaf = await client.getAccountLeaf(i, blockNumber);
///   builder.setLeaf(i, leaf);
/// }
///
/// // Query and set inner nodes
/// const nodeLocations = builder.getNodeLocations();
/// for (let i = 0; i < nodeLocations.length; i++) {
///   const node = await client.getAccountInnerNode(nodeLocations[i], blockNumber);
///   builder.setNodeAtIndex(i, node);
/// }
///
/// // Query and set root
/// const root = await client.getAccountTreeRoot(blockNumber);
/// builder.setRoot(root);
///
/// // Build the path
/// const pathAndRoot = builder.buildLeafPathWithRoot();
/// ```
#[wasm_bindgen]
#[derive(Clone)]
pub struct AccountLeafPathBuilder {
    pub(crate) tree: AccountLeafPathBuilderType,
}

#[wasm_bindgen]
impl AccountLeafPathBuilder {
    /// Creates a new account leaf path builder.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the tree (typically from account state)
    /// * `height` - The height of the tree (typically 4 for account trees)
    /// * `block_number` - The block number at which to build the path
    ///
    /// # Returns
    /// A new `AccountLeafPathBuilder` instance ready to collect tree data.
    ///
    /// # Example
    /// ```javascript
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const blockNumber = await accountCurveTree.getLastBlockNumber();
    /// const leafIndex = accountState.leafIndex();
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(leaf_index: LeafIndex, height: NodeLevel, block_number: BlockNumber) -> Self {
        let backend = LeafPathBuilder::new(leaf_index, height, block_number);
        Self {
            tree: CurveTreeWithBackend::new_with_backend(backend)
                .expect("LeafPathBuilder backend; qed"),
        }
    }

    /// Returns the `L` parameter of the account tree.
    ///
    /// This represents the branching factor (arity) of the tree - how many children each node has.
    ///
    /// # Returns
    /// The tree arity as a number (typically 4 for account trees).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// console.log(`Tree arity: ${builder.getL()}`); // 4
    /// ```
    #[wasm_bindgen(js_name = getL)]
    pub fn get_l(&self) -> usize {
        ACCOUNT_TREE_L
    }

    /// Returns the `M` parameter of the account tree.
    ///
    /// This represents the maximum number of children stored in each compressed inner node.
    ///
    /// # Returns
    /// The compression parameter as a number.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// console.log(`Compression parameter: ${builder.getM()}`);
    /// ```
    #[wasm_bindgen(js_name = getM)]
    pub fn get_m(&self) -> usize {
        ACCOUNT_TREE_M
    }

    /// Gets the list of inner node locations that need to be queried from the blockchain.
    ///
    /// Returns an array of SCALE-encoded node locations. These should be used to query
    /// the on-chain storage for inner nodes.
    ///
    /// # Returns
    /// An array of `Uint8Array` values, each representing a SCALE-encoded node location.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAccountInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getNodeLocations)]
    pub fn get_node_locations(&self) -> Vec<Uint8Array> {
        self.tree
            .backend
            .node_locations
            .iter()
            .map(|loc| loc.encode().as_slice().into())
            .collect()
    }

    /// Gets the list of leaf indices that need to be queried from the blockchain.
    ///
    /// Returns all sibling leaf indices along the path to the target leaf.
    ///
    /// # Returns
    /// An array of leaf indices (as numbers).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const leafIndices = builder.getLeafIndices();
    /// for (const index of leafIndices) {
    ///   const leaf = await client.getAccountLeaf(index, blockNumber);
    ///   builder.setLeaf(index, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getLeafIndices)]
    pub fn get_leaf_indices(&self) -> Vec<LeafIndex> {
        self.tree.backend.leaf_indices.clone()
    }

    /// Gets the minimum leaf index that needs to be queried.
    ///
    /// Combined with `getMaxLeafIndex()`, this defines a range of leaves to query.
    ///
    /// # Returns
    /// The minimum leaf index as a number.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAccountLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getMinLeafIndex)]
    pub fn get_min_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_min_leaf_index()
    }

    /// Gets the maximum leaf index that needs to be queried.
    ///
    /// Combined with `getMinLeafIndex()`, this defines a range of leaves to query.
    ///
    /// # Returns
    /// The maximum leaf index as a number (exclusive - use `i < maxLeaf` in loops).
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAccountLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getMaxLeafIndex)]
    pub fn get_max_leaf_index(&self) -> LeafIndex {
        self.tree.backend.get_max_leaf_index()
    }

    /// Sets the tree root value.
    ///
    /// # Arguments
    /// * `root` - A `Uint8Array` containing the SCALE-encoded tree root
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const root = await client.getAccountTreeRoot(blockNumber);
    /// builder.setRoot(root);
    /// ```
    #[wasm_bindgen(js_name = setRoot)]
    pub fn set_root(&mut self, root: &[u8]) {
        self.tree.backend.set_root(root);
    }

    /// Sets a leaf value at the specified index.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the leaf in the tree
    /// * `leaf` - A `Uint8Array` containing the SCALE-encoded leaf value, or `null`/`undefined` to remove
    ///
    /// # Errors
    /// * Throws an error if the leaf data cannot be decoded.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const leaf = await client.getAccountLeaf(0, blockNumber);
    /// builder.setLeaf(0, leaf);
    /// ```
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

    /// Sets an inner node at the specified location index.
    ///
    /// The location index corresponds to the position in the array returned by `getNodeLocations()`.
    ///
    /// # Arguments
    /// * `location_index` - The index in the node locations array
    /// * `node` - A `Uint8Array` containing the SCALE-encoded inner node, or `null`/`undefined` to remove
    ///
    /// # Errors
    /// * Throws an error if the location index is out of bounds.
    /// * Throws an error if the node data cannot be decoded.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAccountInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    /// ```
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

    /// Builds the account leaf path with the root included.
    ///
    /// Constructs the complete curve tree path from the target leaf to the root, including the root value.
    /// This is used when generating zero-knowledge proofs about account states.
    ///
    /// # Returns
    /// An `AccountLeafPathAndRoot` instance containing both the curve tree path and the root.
    ///
    /// # Errors
    /// * Throws an error if required leaves, nodes, or root have not been set.
    /// * Throws an error if the path cannot be constructed.
    ///
    /// # Example
    /// ```javascript
    /// const builder = new AccountLeafPathBuilder(leafIndex, 4, blockNumber);
    ///
    /// // Set all leaves
    /// const minLeaf = builder.getMinLeafIndex();
    /// const maxLeaf = builder.getMaxLeafIndex();
    /// for (let i = minLeaf; i < maxLeaf; i++) {
    ///   const leaf = await client.getAccountLeaf(i, blockNumber);
    ///   builder.setLeaf(i, leaf);
    /// }
    ///
    /// // Set all inner nodes
    /// const nodeLocations = builder.getNodeLocations();
    /// for (let i = 0; i < nodeLocations.length; i++) {
    ///   const node = await client.getAccountInnerNode(nodeLocations[i], blockNumber);
    ///   builder.setNodeAtIndex(i, node);
    /// }
    ///
    /// // Set the root
    /// const root = await client.getAccountTreeRoot(blockNumber);
    /// builder.setRoot(root);
    ///
    /// // Build the complete path with root
    /// const pathAndRoot = builder.buildLeafPathWithRoot();
    /// ```
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
