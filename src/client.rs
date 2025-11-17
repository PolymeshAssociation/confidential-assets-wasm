use futures_util::StreamExt;
use js_sys::Uint8Array;

use codec::{Decode, Encode};
use polymesh_api::{Api, ChainApi};
use polymesh_api_client::{DefaultSigner, Signer};
use polymesh_dart::{
    AssetId, AssetState as NativeAssetState, BlockNumber, LeafIndex, WrappedCanonical,
};
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
///
/// This is the main entry point for interacting with the Polymesh blockchain.
/// It provides methods to query on-chain data, submit transactions, and access
/// the various curve trees (account, asset, and fee account trees).
#[wasm_bindgen]
pub struct PolymeshClient {
    pub(crate) api: Api,
    pub(crate) finalize: bool,
}

#[wasm_bindgen]
impl PolymeshClient {
    /// Connects to a Polymesh node via WebSocket.
    ///
    /// Establishes a connection to the specified Polymesh node and initializes the API client.
    /// This is typically the first method called when working with the library.
    ///
    /// # Arguments
    /// * `url` - The WebSocket URL of the Polymesh node (e.g., `"ws://localhost:9944"` or `"wss://dev.polymesh.tech/dart/dev/"`)
    ///
    /// # Returns
    /// A connected `PolymeshClient` instance.
    ///
    /// # Errors
    /// * Throws an error if the connection to the node fails.
    /// * Throws an error if the node is unreachable or returns invalid metadata.
    ///
    /// # Example
    /// ```javascript
    /// // Connect to local node
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    ///
    /// // Connect to testnet
    /// const client = await PolymeshClient.connect("wss://dev.polymesh.tech/dart/dev/");
    /// ```
    #[wasm_bindgen]
    pub async fn connect(url: &str) -> Result<Self, JsValue> {
        let url = url.to_string();
        let api = Api::new(&url)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to connect to node: {}", e)))?;
        Ok(PolymeshClient {
            api,
            finalize: true,
        })
    }

    /// Sets whether to wait for transaction finalization.
    ///
    /// When set to `true` (default), transactions will wait for finalization before returning.
    /// When set to `false`, transactions will return as soon as they are included in a block,
    /// which is faster but provides weaker guarantees.
    ///
    /// # Arguments
    /// * `finalize` - Whether to wait for transaction finalization
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    ///
    /// // Disable finalization for faster testing
    /// client.finalize = false;
    ///
    /// // Re-enable finalization for production
    /// client.finalize = true;
    /// ```
    #[wasm_bindgen(setter)]
    pub fn set_finalize(&mut self, finalize: bool) {
        self.finalize = finalize;
    }

    /// Gets a handle to the asset curve tree for querying asset states.
    ///
    /// The asset curve tree stores commitments to all confidential assets in the system.
    /// Use this to query asset leaf paths, roots, and build proofs for settlements.
    ///
    /// # Returns
    /// An `AssetCurveTree` instance for querying the asset tree.
    ///
    /// # Errors
    /// * Throws an error if the curve tree cannot be initialized.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    /// const assetPath = await assetCurveTree.getLeafPathAndRoot(assetLeafIndex, blockNumber);
    /// ```
    #[wasm_bindgen(js_name = getAssetCurveTree)]
    pub async fn get_asset_curve_tree(&self) -> Result<AssetCurveTree, JsValue> {
        let tree = curve_tree::AssetCurveTree::new(&self.api)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get asset curve tree: {}", e)))?;
        Ok(AssetCurveTree { inner: tree })
    }

    /// Gets a handle to the account curve tree for querying account states.
    ///
    /// The account curve tree stores commitments to all confidential account balances.
    /// Use this to query account leaf paths and build proofs for balance-related operations.
    ///
    /// # Returns
    /// An `AccountCurveTree` instance for querying the account tree.
    ///
    /// # Errors
    /// * Throws an error if the curve tree cannot be initialized.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const blockNumber = await accountCurveTree.getLastBlockNumber();
    /// const accountPath = await accountCurveTree.getLeafPathAndRoot(accountLeafIndex, blockNumber);
    /// ```
    #[wasm_bindgen(js_name = getAccountCurveTree)]
    pub async fn get_account_curve_tree(&self) -> Result<AccountCurveTree, JsValue> {
        let tree = curve_tree::AccountCurveTree::new(&self.api)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get account curve tree: {}", e)))?;
        Ok(AccountCurveTree { inner: tree })
    }

    /// Gets a handle to the fee account curve tree.
    ///
    /// The fee account curve tree stores commitments related to fee accounts.
    ///
    /// # Returns
    /// A `FeeAccountCurveTree` instance for querying the fee account tree.
    ///
    /// # Errors
    /// * Throws an error if the curve tree cannot be initialized.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const feeAccountCurveTree = await client.getFeeAccountCurveTree();
    /// ```
    #[wasm_bindgen(js_name = getFeeAccountCurveTree)]
    pub async fn get_fee_account_curve_tree(&self) -> Result<FeeAccountCurveTree, JsValue> {
        let tree = curve_tree::FeeAccountCurveTree::new(&self.api)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to get fee account curve tree: {}", e))
            })?;
        Ok(FeeAccountCurveTree { inner: tree })
    }

    /// Creates a new signer from a seed phrase or private key.
    ///
    /// The signer can be used to submit transactions to the blockchain.
    /// The seed string supports various formats including mnemonic phrases,
    /// hex-encoded private keys, and Substrate development accounts (e.g., "//Alice").
    ///
    /// # Arguments
    /// * `s` - A seed phrase, private key, or development account identifier
    ///
    /// # Returns
    /// A `PolymeshSigner` instance ready to submit transactions.
    ///
    /// # Errors
    /// * Throws an error if the seed string cannot be parsed into a valid keypair.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    ///
    /// // Create signer from development account
    /// const issuer = client.newSigner("//TestIssuer");
    ///
    /// // Create signer from mnemonic
    /// const investor = client.newSigner("bottom drive obey lake curtain smoke basket hold race lonely fit walk");
    /// ```
    #[wasm_bindgen(js_name = newSigner)]
    pub fn new_signer(&self, s: &str) -> Result<PolymeshSigner, JsValue> {
        let signer = DefaultSigner::from_string(s, None)
            .map_err(|e| JsValue::from_str(&format!("Failed to create signer: {}", e)))?;
        Ok(PolymeshSigner::new(signer, &self.api, self.finalize))
    }

    /// Onboard a new signer (CDD + POLYX funding).
    ///
    /// This is only supported on a development/test chains.
    #[wasm_bindgen(js_name = onboardSigner)]
    pub async fn onboard_signer(&self, new_signer: &PolymeshSigner) -> Result<(), JsValue> {
        let account_id = new_signer.signer.account();
        // Use `Alice` to onboard the new signer
        let mut alice = PolymeshSigner::alice(&self.api, self.finalize);

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

    /// Get an account leaf at the given index for a specific block number.
    #[wasm_bindgen(js_name = getAccountLeaf)]
    pub async fn get_account_leaf(
        &self,
        leaf_index: LeafIndex,
        block_number: BlockNumber,
    ) -> Result<Option<Uint8Array>, JsValue> {
        let block_hash = self
            .api
            .client()
            .get_block_hash(block_number)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to get block hash for block number {}: {}",
                    block_number, e
                ))
            })?
            .ok_or_else(|| {
                JsValue::from_str(&format!(
                    "No block hash found for block number {}",
                    block_number
                ))
            })?;
        let leaf = self
            .api
            .query_at(block_hash)
            .confidential_assets()
            .account_leaves(leaf_index)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query account leaf: {}", e)))?;
        if let Some(leaf) = leaf {
            return Ok(Some(leaf.encode().as_slice().into()));
        }
        Ok(None)
    }

    /// Get an account inner node at the given location for a specific block number.
    #[wasm_bindgen(js_name = getAccountInnerNode)]
    pub async fn get_account_inner_node(
        &self,
        location: Uint8Array,
        block_number: BlockNumber,
    ) -> Result<Option<Uint8Array>, JsValue> {
        let location = location.to_vec();
        let location = Decode::decode(&mut &location[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode account inner node location: {}",
                e
            ))
        })?;
        log::info!(
            "Getting account inner node at location: {:?} for block number: {:?}",
            location,
            block_number
        );
        let block_hash = self
            .api
            .client()
            .get_block_hash(block_number)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to get block hash for block number {}: {}",
                    block_number, e
                ))
            })?
            .ok_or_else(|| {
                JsValue::from_str(&format!(
                    "No block hash found for block number {}",
                    block_number
                ))
            })?;
        let node = self
            .api
            .query_at(block_hash)
            .confidential_assets()
            .account_inner_nodes(location)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to query account inner node: {}", e))
            })?;
        if let Some(node) = node {
            return Ok(Some(node.encode().as_slice().into()));
        }
        Ok(None)
    }

    /// Get the Account tree root.
    #[wasm_bindgen(js_name = getAccountTreeRoot)]
    pub async fn get_account_tree_root(
        &self,
        block_number: BlockNumber,
    ) -> Result<Uint8Array, JsValue> {
        let root = self
            .api
            .query()
            .confidential_assets()
            .account_curve_tree_roots(block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query account tree root: {}", e)))?;
        if let Some(root) = root {
            Ok(root.encode().as_slice().into())
        } else {
            Err(JsValue::from_str(&format!(
                "No account tree root found for block number {}",
                block_number
            )))
        }
    }

    /// Get an asset leaf at the given index for a specific block number.
    #[wasm_bindgen(js_name = getAssetLeaf)]
    pub async fn get_asset_leaf(
        &self,
        leaf_index: LeafIndex,
        block_number: BlockNumber,
    ) -> Result<Option<Uint8Array>, JsValue> {
        let block_hash = self
            .api
            .client()
            .get_block_hash(block_number)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to get block hash for block number {}: {}",
                    block_number, e
                ))
            })?
            .ok_or_else(|| {
                JsValue::from_str(&format!(
                    "No block hash found for block number {}",
                    block_number
                ))
            })?;
        let leaf = self
            .api
            .query_at(block_hash)
            .confidential_assets()
            .asset_leaves(leaf_index)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query asset leaf: {}", e)))?;
        if let Some(leaf) = leaf {
            return Ok(Some(leaf.encode().as_slice().into()));
        }
        Ok(None)
    }

    /// Get an asset inner node at the given location for a specific block number.
    #[wasm_bindgen(js_name = getAssetInnerNode)]
    pub async fn get_asset_inner_node(
        &self,
        location: Uint8Array,
        block_number: BlockNumber,
    ) -> Result<Option<Uint8Array>, JsValue> {
        let location = location.to_vec();
        let location = Decode::decode(&mut &location[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode asset inner node location: {}",
                e
            ))
        })?;
        log::info!(
            "Getting asset inner node at location: {:?} for block number: {:?}",
            location,
            block_number
        );
        let block_hash = self
            .api
            .client()
            .get_block_hash(block_number)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to get block hash for block number {}: {}",
                    block_number, e
                ))
            })?
            .ok_or_else(|| {
                JsValue::from_str(&format!(
                    "No block hash found for block number {}",
                    block_number
                ))
            })?;
        let node = self
            .api
            .query_at(block_hash)
            .confidential_assets()
            .asset_inner_nodes(location)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query asset inner node: {}", e)))?;
        if let Some(node) = node {
            return Ok(Some(node.encode().as_slice().into()));
        }
        Ok(None)
    }

    /// Get the Asset tree root.
    #[wasm_bindgen(js_name = getAssetTreeRoot)]
    pub async fn get_asset_tree_root(
        &self,
        block_number: BlockNumber,
    ) -> Result<Uint8Array, JsValue> {
        let root = self
            .api
            .query()
            .confidential_assets()
            .asset_curve_tree_roots(block_number)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query asset tree root: {}", e)))?;
        if let Some(root) = root {
            Ok(root.encode().as_slice().into())
        } else {
            Err(JsValue::from_str(&format!(
                "No asset tree root found for block number {}",
                block_number
            )))
        }
    }
}

/// The Fee Account curve tree.
///
/// Provides access to query fee account states from the on-chain curve tree.
/// Fee accounts track transaction fees in the confidential asset system.
#[wasm_bindgen]
pub struct FeeAccountCurveTree {
    pub(crate) inner: curve_tree::FeeAccountCurveTree,
}

#[wasm_bindgen]
impl FeeAccountCurveTree {
    /// Retrieves the curve tree path and root for a specific fee account leaf.
    ///
    /// This method queries the blockchain and constructs the complete path from the
    /// specified leaf to the tree root. If no block number is provided, the latest
    /// finalized block is used.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the fee account tree
    /// * `block_number` - Optional block number at which to query the tree state (uses latest if not provided)
    ///
    /// # Returns
    /// A `FeeAccountLeafPathAndRoot` containing the curve tree path and root.
    ///
    /// # Errors
    /// * Throws an error if the leaf path cannot be retrieved from the blockchain.
    /// * Throws an error if the specified block number is invalid or too old.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const feeAccountCurveTree = await client.getFeeAccountCurveTree();
    ///
    /// // Get latest path
    /// const pathAndRoot = await feeAccountCurveTree.getLeafPathAndRoot(leafIndex);
    ///
    /// // Get path at specific block
    /// const blockNumber = 12345;
    /// const historicalPath = await feeAccountCurveTree.getLeafPathAndRoot(leafIndex, blockNumber);
    /// ```
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

    /// Gets the block number of the most recently updated tree root.
    ///
    /// This is useful for determining which block to use when querying historical tree states.
    ///
    /// # Returns
    /// The block number as a `u32`.
    ///
    /// # Errors
    /// * Throws an error if the block number cannot be queried from the blockchain.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const feeAccountCurveTree = await client.getFeeAccountCurveTree();
    /// const lastBlock = await feeAccountCurveTree.getLastBlockNumber();
    /// console.log(`Fee account tree last updated at block ${lastBlock}`);
    /// ```
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
///
/// Provides access to query account states from the on-chain curve tree.
/// Account states contain commitments to confidential balances for each account-asset pair.
#[wasm_bindgen]
pub struct AccountCurveTree {
    pub(crate) inner: curve_tree::AccountCurveTree,
}

#[wasm_bindgen]
impl AccountCurveTree {
    /// Retrieves the curve tree path and root for a specific account leaf.
    ///
    /// This method queries the blockchain and constructs the complete path from the
    /// specified leaf to the tree root. Account leaves contain balance commitments
    /// for account-asset pairs. If no block number is provided, the latest finalized block is used.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the account tree (typically from `accountAssetState.leafIndex()`)
    /// * `block_number` - Optional block number at which to query the tree state (uses latest if not provided)
    ///
    /// # Returns
    /// An `AccountLeafPathAndRoot` containing the curve tree path and root.
    ///
    /// # Errors
    /// * Throws an error if the leaf path cannot be retrieved from the blockchain.
    /// * Throws an error if the specified block number is invalid or too old.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const accountCurveTree = await client.getAccountCurveTree();
    ///
    /// // Get latest path for generating proofs
    /// const leafIndex = accountAssetState.leafIndex();
    /// const pathAndRoot = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    ///
    /// // Get path at specific block for historical proofs
    /// const blockNumber = 12345;
    /// const historicalPath = await accountCurveTree.getLeafPathAndRoot(leafIndex, blockNumber);
    /// ```
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

    /// Gets the block number of the most recently updated tree root.
    ///
    /// This is useful for determining which block to use when generating proofs.
    /// Proofs must reference a specific block's root to be valid.
    ///
    /// # Returns
    /// The block number as a `u32`.
    ///
    /// # Errors
    /// * Throws an error if the block number cannot be queried from the blockchain.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const lastBlock = await accountCurveTree.getLastBlockNumber();
    /// console.log(`Account tree last updated at block ${lastBlock}`);
    ///
    /// // Use this block number for proof generation
    /// const pathAndRoot = await accountCurveTree.getLeafPathAndRoot(leafIndex, lastBlock);
    /// ```
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
///
/// Provides access to query asset states from the on-chain curve tree.
/// Asset states contain metadata about confidential assets including mediator and auditor keys.
#[wasm_bindgen]
pub struct AssetCurveTree {
    pub(crate) inner: curve_tree::AssetCurveTree,
}

#[wasm_bindgen]
impl AssetCurveTree {
    /// Retrieves the curve tree path and root for a specific asset leaf.
    ///
    /// This method queries the blockchain and constructs the complete path from the
    /// specified leaf to the tree root. Asset leaves contain metadata about confidential
    /// assets. If no block number is provided, the latest finalized block is used.
    ///
    /// This is commonly used when building settlement proofs, as the asset path is required
    /// to prove the asset state at a specific block.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the asset tree (typically from `assetState.leafIndex()`)
    /// * `block_number` - Optional block number at which to query the tree state (uses latest if not provided)
    ///
    /// # Returns
    /// An `AssetLeafPathAndRoot` containing the curve tree path and root.
    ///
    /// # Errors
    /// * Throws an error if the leaf path cannot be retrieved from the blockchain.
    /// * Throws an error if the specified block number is invalid or too old.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const assetCurveTree = await client.getAssetCurveTree();
    ///
    /// // Get the latest block number
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    ///
    /// // Get asset state and its path
    /// const assetState = await client.getAssetState(assetId);
    /// const assetLeafIndex = assetState.leafIndex();
    /// const assetPath = await assetCurveTree.getLeafPathAndRoot(assetLeafIndex, blockNumber);
    ///
    /// // Use in settlement builder
    /// const settlementBuilder = new SettlementBuilder("memo", blockNumber, assetPath.getRoot());
    /// settlementBuilder.addAssetPath(assetId, assetPath);
    /// ```
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

    /// Gets the block number of the most recently updated tree root.
    ///
    /// This is critical for settlement proof generation, as the proof must reference
    /// a specific block's root. Always use this to get the current block before building settlements.
    ///
    /// # Returns
    /// The block number as a `u32`.
    ///
    /// # Errors
    /// * Throws an error if the block number cannot be queried from the blockchain.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const assetCurveTree = await client.getAssetCurveTree();
    ///
    /// // Get the latest block for proof generation
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    /// const assetTreeRoot = await assetCurveTree.getRoot(blockNumber);
    ///
    /// // Use in settlement builder
    /// const settlementBuilder = new SettlementBuilder("Transfer", blockNumber, assetTreeRoot);
    /// ```
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

    /// Retrieves the asset tree root at a specific block.
    ///
    /// The root is a commitment to all asset states in the tree. This is required
    /// when building settlement proofs.
    ///
    /// # Arguments
    /// * `block_number` - Optional block number at which to query the root (uses latest if not provided)
    ///
    /// # Returns
    /// An `AssetTreeRoot` instance.
    ///
    /// # Errors
    /// * Throws an error if the root cannot be retrieved from the blockchain.
    /// * Throws an error if the specified block number is invalid.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const assetCurveTree = await client.getAssetCurveTree();
    ///
    /// // Get latest root
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    /// const root = await assetCurveTree.getRoot(blockNumber);
    ///
    /// // Use in settlement builder
    /// const settlementBuilder = new SettlementBuilder("Transfer", blockNumber, root);
    /// ```
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

    /// Retrieves only the curve tree path for a specific asset leaf (without the root).
    ///
    /// This is less commonly used than `getLeafPathAndRoot()`. Most operations require
    /// both the path and root together.
    ///
    /// # Arguments
    /// * `leaf_index` - The index of the target leaf in the asset tree
    /// * `block_number` - Optional block number at which to query the tree state (uses latest if not provided)
    ///
    /// # Returns
    /// An `AssetLeafPath` containing only the curve tree path.
    ///
    /// # Errors
    /// * Throws an error if the leaf path cannot be retrieved from the blockchain.
    /// * Throws an error if the specified block number is invalid or too old.
    ///
    /// # Example
    /// ```javascript
    /// const client = await PolymeshClient.connect("ws://localhost:9944");
    /// const assetCurveTree = await client.getAssetCurveTree();
    /// const assetLeafIndex = assetState.leafIndex();
    /// const path = await assetCurveTree.getLeafPath(assetLeafIndex);
    /// ```
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
