use codec::Encode;
use core::ops::{Deref, DerefMut};
use std::collections::BTreeMap;

use polymesh_dart::{
    curve_tree::{
        AccountTreeConfig, AssetTreeConfig, AsyncCurveTreeBackend, AsyncCurveTreeWithBackend,
        CompressedCurveTreeRoot, CompressedInner, CompressedLeafValue, CurveTreeConfig,
        CurveTreeLookup, CurveTreeParameters, CurveTreePath, DefaultCurveTreeUpdater,
        FeeAccountTreeConfig, LeafPathAndRoot, NodeLocation, NodePosition,
    },
    AssetId, AssetState, BlockNumber, Error as DartError, LeafIndex, NodeLevel,
    ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_HEIGHT, ASSET_TREE_L,
    ASSET_TREE_M, FEE_ACCOUNT_TREE_HEIGHT, FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M,
};

use polymesh_api::{
    types::polymesh_dart::curve_tree::common::{
        NodeLocation as ChainNodeLocation, NodePosition as ChainNodePosition,
    },
    Api, ChainApi as _,
};

use crate::{scale_convert, Error, Result};

pub type AssetLeaf = CompressedLeafValue<AssetTreeConfig>;
pub type AssetLeafPath = LeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;
pub type AssetInnerNode = CompressedInner<ASSET_TREE_M, AssetTreeConfig>;
pub type AssetNodeLocation = NodeLocation<ASSET_TREE_L>;
pub type AssetTreeRoot = CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

pub type AccountLeaf = CompressedLeafValue<AccountTreeConfig>;
pub type AccountLeafPath = LeafPathAndRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AccountInnerNode = CompressedInner<ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;
pub type AccountTreeRoot =
    CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

pub type FeeAccountLeaf = CompressedLeafValue<FeeAccountTreeConfig>;
pub type FeeAccountLeafPath =
    LeafPathAndRoot<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;
pub type FeeAccountInnerNode = CompressedInner<FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;
pub type FeeAccountNodeLocation = NodeLocation<FEE_ACCOUNT_TREE_L>;
pub type FeeAccountTreeRoot =
    CompressedCurveTreeRoot<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;

/// Convert off-chain `NodeLocation` to on-chain `NodeLocation`.
pub fn node_location_to_chain<const L: usize>(location: NodeLocation<L>) -> ChainNodeLocation {
    match location {
        NodeLocation::Leaf(leaf_index) => ChainNodeLocation::Leaf(leaf_index),
        NodeLocation::Odd(NodePosition { level, index }) => {
            ChainNodeLocation::Odd(ChainNodePosition { level, index })
        }
        NodeLocation::Even(NodePosition { level, index }) => {
            ChainNodeLocation::Even(ChainNodePosition { level, index })
        }
    }
}

/// Asset Curve Tree Storage backend.
#[derive(Clone)]
pub struct AssetCurveTreeChainStorage {
    pub(crate) api: Api,
}

impl AssetCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self { api: api.clone() }
    }
}

impl AsyncCurveTreeBackend<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>
    for AssetCurveTreeChainStorage
{
    type Error = Error;
    type Updater = DefaultCurveTreeUpdater<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

    async fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Err(Error::other(
            "AssetCurveTreeChainStorage does not support new()",
        ))
    }

    fn parameters(&self) -> &CurveTreeParameters<AssetTreeConfig> {
        AssetTreeConfig::parameters()
    }

    async fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        let last_block_number = self
            .api
            .query()
            .confidential_assets()
            .asset_curve_tree_last_update()
            .await?;
        Ok(last_block_number)
    }

    async fn fetch_root(&self, block_number: Option<BlockNumber>) -> Result<AssetTreeRoot> {
        let root = if let Some(block_number) = block_number {
            self.api
                .query()
                .confidential_assets()
                .asset_curve_tree_roots(block_number)
                .await?
        } else {
            self.api
                .query()
                .confidential_assets()
                .asset_curve_tree_current_root()
                .await?
        };
        if let Some(root) = root {
            Ok(scale_convert(&root))
        } else {
            Err(Error::Other(format!(
                "Root not found for block number {:?}",
                block_number
            )))
        }
    }

    async fn height(&self) -> NodeLevel {
        ASSET_TREE_HEIGHT
    }

    async fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    async fn get_leaf(
        &self,
        leaf_index: LeafIndex,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<AssetLeaf>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        if let Some(block_hash) = block_hash {
            if let Some(leaf) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .asset_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        } else {
            if let Some(leaf) = self
                .api
                .query()
                .confidential_assets()
                .asset_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        }
        Ok(None)
    }

    async fn leaf_count(&self) -> LeafIndex {
        0
    }

    async fn get_inner_node(
        &self,
        location: NodeLocation<ASSET_TREE_L>,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<AssetInnerNode>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        let location = node_location_to_chain(location);
        if let Some(block_hash) = block_hash {
            if let Some(node) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .asset_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        } else {
            if let Some(node) = self
                .api
                .query()
                .confidential_assets()
                .asset_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        }
        Ok(None)
    }
}

pub type AssetCurveTreeType = AsyncCurveTreeWithBackend<
    ASSET_TREE_L,
    ASSET_TREE_M,
    AssetTreeConfig,
    AssetCurveTreeChainStorage,
    Error,
>;

#[derive(Clone)]
pub struct AssetCurveTree(AssetCurveTreeType);

impl Deref for AssetCurveTree {
    type Target = AssetCurveTreeType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AssetCurveTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AssetCurveTree {
    pub async fn new(api: &Api) -> Result<Self> {
        let backend = AssetCurveTreeChainStorage::new(api);
        Ok(Self(
            AsyncCurveTreeWithBackend::new_with_backend(backend).await?,
        ))
    }
}

/// A syncronous holder for multiple asset leaf paths.
///
/// This is used for creating multi-leg settlements that have different assets.
pub struct AssetLeafPaths {
    pub track_assets: BTreeMap<AssetId, AssetState>,
    pub leaf_index: BTreeMap<Vec<u8>, LeafIndex>,
    pub paths: BTreeMap<LeafIndex, CurveTreePath<ASSET_TREE_L, AssetTreeConfig>>,
    pub block_number: BlockNumber,
    pub root: AssetTreeRoot,
}

impl AssetLeafPaths {
    pub async fn new(asset_tree: &AssetCurveTreeType) -> Result<Self> {
        let block_number = asset_tree.get_block_number().await?;
        let root = asset_tree.fetch_root(Some(block_number)).await?;
        Ok(Self {
            track_assets: BTreeMap::new(),
            leaf_index: BTreeMap::new(),
            paths: BTreeMap::new(),
            block_number,
            root,
        })
    }

    async fn update_asset_path(
        &mut self,
        asset_id: AssetId,
        asset_tree: &AssetCurveTreeType,
        api: &Api,
    ) -> Result<AssetState> {
        let leaf_index = asset_id as _;
        let leaf = asset_tree
            .get_leaf(leaf_index, Some(self.block_number))
            .await?
            .ok_or_else(|| DartError::LeafIndexNotFound(leaf_index))?;
        let path = asset_tree
            .get_path_to_leaf(leaf_index, 0, Some(self.block_number))
            .await?;
        self.leaf_index.insert(leaf.encode(), leaf_index);
        self.paths.insert(leaf_index, path);

        // Get DART asset details.
        let details = api
            .query()
            .confidential_assets()
            .dart_asset_details(asset_id)
            .await
            .map_err(|err| Error::from(err))?
            .ok_or_else(|| Error::not_found("Dart asset doesn't exist"))?;
        let asset_state = AssetState {
            asset_id,
            auditors: scale_convert(&details.auditors),
            mediators: scale_convert(&details.mediators),
        };
        self.track_assets.insert(asset_id, asset_state.clone());

        Ok(asset_state)
    }

    pub async fn update_root(&mut self, asset_tree: &AssetCurveTreeType) -> Result<()> {
        self.block_number = asset_tree.get_block_number().await?;
        self.root = asset_tree.fetch_root(Some(self.block_number)).await?;
        Ok(())
    }

    pub async fn track_asset(
        &mut self,
        asset_id: AssetId,
        asset_tree: &AssetCurveTreeType,
        api: &Api,
    ) -> Result<AssetState> {
        if let Some(asset_state) = self.track_assets.get(&asset_id) {
            Ok(asset_state.clone())
        } else {
            return self.update_asset_path(asset_id, asset_tree, api).await;
        }
    }
}

impl CurveTreeLookup<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig> for AssetLeafPaths {
    fn get_path_to_leaf_index(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<CurveTreePath<ASSET_TREE_L, AssetTreeConfig>, DartError> {
        if let Some(path) = self.paths.get(&leaf_index) {
            Ok(path.clone())
        } else {
            Err(DartError::LeafIndexNotFound(leaf_index))
        }
    }

    fn get_path_to_leaf(
        &self,
        leaf: AssetLeaf,
    ) -> Result<CurveTreePath<ASSET_TREE_L, AssetTreeConfig>, DartError> {
        let leaf_buf = leaf.encode();
        let leaf_index = self
            .leaf_index
            .get(&leaf_buf)
            .ok_or(DartError::LeafNotFound)?;
        self.get_path_to_leaf_index(*leaf_index)
    }

    fn params(&self) -> &CurveTreeParameters<AssetTreeConfig> {
        AssetTreeConfig::parameters()
    }

    fn get_block_number(&self) -> Result<BlockNumber, DartError> {
        Ok(self.block_number)
    }

    fn root(&self) -> Result<AssetTreeRoot, DartError> {
        Ok(self.root.clone())
    }
}

/// Account Curve Tree Storage backend.
#[derive(Clone)]
pub struct AccountCurveTreeChainStorage {
    pub(crate) api: Api,
}

impl AccountCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self { api: api.clone() }
    }
}

impl AsyncCurveTreeBackend<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>
    for AccountCurveTreeChainStorage
{
    type Error = Error;
    type Updater = DefaultCurveTreeUpdater<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

    async fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Err(Error::other(
            "AccountCurveTreeChainStorage does not support new()",
        ))
    }

    fn parameters(&self) -> &CurveTreeParameters<AccountTreeConfig> {
        AccountTreeConfig::parameters()
    }

    async fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        let last_block_number = self
            .api
            .query()
            .confidential_assets()
            .account_curve_tree_last_update()
            .await?;
        Ok(last_block_number)
    }

    async fn fetch_root(&self, block_number: Option<BlockNumber>) -> Result<AccountTreeRoot> {
        let root = if let Some(block_number) = block_number {
            self.api
                .query()
                .confidential_assets()
                .account_curve_tree_roots(block_number)
                .await?
        } else {
            self.api
                .query()
                .confidential_assets()
                .account_curve_tree_current_root()
                .await?
        };
        if let Some(root) = root {
            Ok(scale_convert(&root))
        } else {
            Err(Error::Other(format!(
                "Root not found for block number {:?}",
                block_number
            )))
        }
    }

    async fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
    }

    async fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    async fn get_leaf(
        &self,
        leaf_index: LeafIndex,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<AccountLeaf>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        if let Some(block_hash) = block_hash {
            if let Some(leaf) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .account_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        } else {
            if let Some(leaf) = self
                .api
                .query()
                .confidential_assets()
                .account_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        }
        Ok(None)
    }

    async fn leaf_count(&self) -> LeafIndex {
        0
    }

    async fn get_inner_node(
        &self,
        location: NodeLocation<ACCOUNT_TREE_L>,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<AccountInnerNode>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        let location = node_location_to_chain(location);
        if let Some(block_hash) = block_hash {
            if let Some(node) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .account_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        } else {
            if let Some(node) = self
                .api
                .query()
                .confidential_assets()
                .account_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        }
        Ok(None)
    }
}

pub type AccountCurveTreeType = AsyncCurveTreeWithBackend<
    ACCOUNT_TREE_L,
    ACCOUNT_TREE_M,
    AccountTreeConfig,
    AccountCurveTreeChainStorage,
    Error,
>;

#[derive(Clone)]
pub struct AccountCurveTree(AccountCurveTreeType);

impl Deref for AccountCurveTree {
    type Target = AccountCurveTreeType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AccountCurveTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AccountCurveTree {
    pub async fn new(api: &Api) -> Result<Self> {
        let backend = AccountCurveTreeChainStorage::new(api);
        Ok(Self(
            AsyncCurveTreeWithBackend::new_with_backend(backend).await?,
        ))
    }
}

/// Fee Account Curve Tree Storage backend.
#[derive(Clone)]
pub struct FeeAccountCurveTreeChainStorage {
    pub(crate) api: Api,
}

impl FeeAccountCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self { api: api.clone() }
    }
}

impl AsyncCurveTreeBackend<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>
    for FeeAccountCurveTreeChainStorage
{
    type Error = Error;
    type Updater =
        DefaultCurveTreeUpdater<FEE_ACCOUNT_TREE_L, FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;

    async fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Err(Error::other(
            "FeeAccountCurveTreeChainStorage does not support new()",
        ))
    }

    fn parameters(&self) -> &CurveTreeParameters<FeeAccountTreeConfig> {
        FeeAccountTreeConfig::parameters()
    }

    async fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        let last_block_number = self
            .api
            .query()
            .confidential_assets()
            .fee_account_curve_tree_last_update()
            .await?;
        Ok(last_block_number)
    }

    async fn fetch_root(&self, block_number: Option<BlockNumber>) -> Result<FeeAccountTreeRoot> {
        let root = if let Some(block_number) = block_number {
            self.api
                .query()
                .confidential_assets()
                .fee_account_curve_tree_roots(block_number)
                .await?
        } else {
            self.api
                .query()
                .confidential_assets()
                .fee_account_curve_tree_current_root()
                .await?
        };
        if let Some(root) = root {
            Ok(scale_convert(&root))
        } else {
            Err(Error::Other(format!(
                "Root not found for block number {:?}",
                block_number
            )))
        }
    }

    async fn height(&self) -> NodeLevel {
        FEE_ACCOUNT_TREE_HEIGHT
    }

    async fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    async fn get_leaf(
        &self,
        leaf_index: LeafIndex,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<FeeAccountLeaf>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        if let Some(block_hash) = block_hash {
            if let Some(leaf) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .fee_account_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        } else {
            if let Some(leaf) = self
                .api
                .query()
                .confidential_assets()
                .fee_account_leaves(leaf_index)
                .await?
            {
                return Ok(Some(scale_convert(&leaf)));
            }
        }
        Ok(None)
    }

    async fn leaf_count(&self) -> LeafIndex {
        0
    }

    async fn get_inner_node(
        &self,
        location: NodeLocation<FEE_ACCOUNT_TREE_L>,
        block_number: Option<BlockNumber>,
    ) -> Result<Option<FeeAccountInnerNode>, Error> {
        let block_hash = match block_number {
            Some(num) => self.api.client().get_block_hash(num).await?,
            None => None,
        };
        let location = node_location_to_chain(location);
        if let Some(block_hash) = block_hash {
            if let Some(node) = self
                .api
                .query_at(block_hash)
                .confidential_assets()
                .fee_account_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        } else {
            if let Some(node) = self
                .api
                .query()
                .confidential_assets()
                .fee_account_inner_nodes(location)
                .await?
            {
                return Ok(Some(scale_convert(&node)));
            }
        }
        Ok(None)
    }
}

pub type FeeAccountCurveTreeType = AsyncCurveTreeWithBackend<
    FEE_ACCOUNT_TREE_L,
    FEE_ACCOUNT_TREE_M,
    FeeAccountTreeConfig,
    FeeAccountCurveTreeChainStorage,
    Error,
>;

#[derive(Clone)]
pub struct FeeAccountCurveTree(FeeAccountCurveTreeType);

impl Deref for FeeAccountCurveTree {
    type Target = FeeAccountCurveTreeType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FeeAccountCurveTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FeeAccountCurveTree {
    pub async fn new(api: &Api) -> Result<Self> {
        let backend = FeeAccountCurveTreeChainStorage::new(api);
        Ok(Self(
            AsyncCurveTreeWithBackend::new_with_backend(backend).await?,
        ))
    }
}
