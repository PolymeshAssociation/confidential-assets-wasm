use core::ops::{Deref, DerefMut};

use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;

use polymesh_dart::{
    curve_tree::{
        AccountTreeConfig, AssetTreeConfig, AsyncCurveTreeBackend, AsyncCurveTreeWithBackend,
        CompressedCurveTreeRoot, CompressedInner, CompressedLeafValue, CurveTreeConfig,
        CurveTreeParameters, DefaultCurveTreeUpdater, FeeAccountTreeConfig, NodeLocation,
        NodePosition,
    },
    BlockNumber, LeafIndex, NodeLevel, ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L, ACCOUNT_TREE_M,
    ASSET_TREE_HEIGHT, ASSET_TREE_L, ASSET_TREE_M, FEE_ACCOUNT_TREE_HEIGHT, FEE_ACCOUNT_TREE_L,
    FEE_ACCOUNT_TREE_M,
};

use polymesh_api::{
    client::BlockHash,
    types::polymesh_dart::curve_tree::common::{
        NodeLocation as ChainNodeLocation, NodePosition as ChainNodePosition,
    },
    Api, ChainApi as _,
};

use crate::{scale_convert, Error, Result};

pub type AssetLeaf = CompressedLeafValue<AssetTreeConfig>;
pub type AssetInnerNode = CompressedInner<ASSET_TREE_M, AssetTreeConfig>;
pub type AssetTreeRoot = CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

pub type AccountLeaf = CompressedLeafValue<AccountTreeConfig>;
pub type AccountInnerNode = CompressedInner<ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AccountTreeRoot =
    CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

pub type FeeAccountLeaf = CompressedLeafValue<FeeAccountTreeConfig>;
pub type FeeAccountInnerNode = CompressedInner<FEE_ACCOUNT_TREE_M, FeeAccountTreeConfig>;
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

/// Block hash cache.
#[derive(Clone, Debug, Default)]
pub struct BlockHashCache {
    // Cache with internal mutability to allow updating
    cache: Arc<RwLock<BTreeMap<BlockNumber, BlockHash>>>,
}

impl BlockHashCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get block hash from cache.
    pub async fn get(&self, block_number: &BlockNumber) -> Option<BlockHash> {
        let cache = self.cache.read().await;
        cache.get(block_number).cloned()
    }

    /// Insert block hash into cache.
    pub async fn insert(&self, block_number: BlockNumber, block_hash: BlockHash) {
        let mut cache = self.cache.write().await;
        cache.insert(block_number, block_hash);
    }
}

/// Polymesh Api with block hash caching.
#[derive(Clone)]
pub struct CachedApi {
    pub(crate) api: Api,
    pub(crate) block_hash_cache: BlockHashCache,
}

impl Deref for CachedApi {
    type Target = Api;

    fn deref(&self) -> &Self::Target {
        &self.api
    }
}

impl CachedApi {
    pub fn new(api: &Api) -> Self {
        Self {
            api: api.clone(),
            block_hash_cache: BlockHashCache::new(),
        }
    }

    /// Get block hash with caching.
    pub async fn get_block_hash(&self, block_number: BlockNumber) -> Result<Option<BlockHash>> {
        if let Some(cached_hash) = self.block_hash_cache.get(&block_number).await {
            return Ok(Some(cached_hash));
        }
        let block_hash = self.api.client().get_block_hash(block_number).await?;
        if let Some(ref hash) = block_hash {
            self.block_hash_cache.insert(block_number, *hash).await;
        }

        Ok(block_hash)
    }
}

/// Asset Curve Tree Storage backend.
#[derive(Clone)]
pub struct AssetCurveTreeChainStorage {
    pub(crate) api: CachedApi,
}

impl AssetCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self {
            api: CachedApi::new(api),
        }
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
            Some(num) => self.api.get_block_hash(num).await?,
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
            Some(num) => self.api.get_block_hash(num).await?,
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

/// Account Curve Tree Storage backend.
#[derive(Clone)]
pub struct AccountCurveTreeChainStorage {
    pub(crate) api: CachedApi,
}

impl AccountCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self {
            api: CachedApi::new(api),
        }
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
            Some(num) => self.api.get_block_hash(num).await?,
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
        log::info!(
            "Getting account inner node at location: {:?} for block number: {:?}",
            location,
            block_number
        );
        let block_hash = match block_number {
            Some(num) => self.api.get_block_hash(num).await?,
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

    async fn get_inner_node_children(
        &self,
        parent: NodeLocation<ACCOUNT_TREE_L>,
        block_number: Option<BlockNumber>,
    ) -> Result<Vec<Option<CompressedInner<ACCOUNT_TREE_M, AccountTreeConfig>>>, Self::Error> {
        log::info!(
            "Getting account inner node children at parent location: {:?} for block number: {:?}",
            parent,
            block_number
        );
        let block_hash = match block_number {
            Some(num) => self.api.get_block_hash(num).await?,
            None => None,
        };

        let query = if let Some(block_hash) = block_hash {
            self.api.query_at(block_hash).confidential_assets()
        } else {
            self.api.query().confidential_assets()
        };
        let mut children = Vec::with_capacity(ACCOUNT_TREE_L);
        for idx in 0..ACCOUNT_TREE_L {
            let location = node_location_to_chain(parent.child(idx as _)?);
            let node = if let Some(node) = query.account_inner_nodes(location).await? {
                Some(scale_convert(&node))
            } else {
                None
            };
            children.push(node);
        }

        Ok(children)
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
    pub(crate) api: CachedApi,
}

impl FeeAccountCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self {
            api: CachedApi::new(api),
        }
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
            Some(num) => self.api.get_block_hash(num).await?,
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
            Some(num) => self.api.get_block_hash(num).await?,
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
