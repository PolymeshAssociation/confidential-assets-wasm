use bounded_collections::{BoundedBTreeSet, TryCollect};

use polymesh_api::{
    types::{
        polymesh_primitives::secondary_key::KeyRecord,
        runtime::{events::*, RuntimeEvent},
    },
    Api, WrappedCall,
};
use polymesh_api_client::{
    AccountId, BlockHash, DefaultSigner, IdentityId, Signer, TransactionResults,
};
use polymesh_dart::{
    AssetState as NativeAssetState, BatchedAccountAssetRegistrationProof, SettlementRef,
};
use wasm_bindgen::prelude::*;

use crate::{
    asset::AssetState, identity_id_to_jsvalue, jsvalue_to_bytes, settlement_ref_to_jsvalue,
};
use crate::{block_hash_to_jsvalue, error::Error};
use crate::{
    keys::{AccountRegistrationProof, EncryptionPublicKey},
    AccountAssetRegistrationProof, SettlementProof,
};
use crate::{scale_convert, AssetMintingProof};

/// Polymesh Signer.
#[wasm_bindgen]
pub struct PolymeshSigner {
    pub(crate) signer: DefaultSigner,
    pub(crate) api: Api,
    pub(crate) finalize: bool,
}

impl PolymeshSigner {
    pub fn new(signer: DefaultSigner, api: &Api, finalize: bool) -> Self {
        PolymeshSigner {
            signer,
            api: api.clone(),
            finalize,
        }
    }

    pub fn alice(api: &Api, finalize: bool) -> Self {
        Self::new(polymesh_api_client::dev::alice(), api, finalize)
    }

    pub(crate) async fn submit_and_watch(
        &mut self,
        call: WrappedCall,
    ) -> Result<TransactionResults<Api>, Error> {
        let mut res = call
            .submit_and_watch(&mut self.signer)
            .await
            .map_err(Error::from)?;

        // Wait for the call to execute.
        if self.finalize {
            res.wait_finalized().await?;
        } else {
            res.wait_in_block().await?;
        }

        Ok(res)
    }

    pub(crate) async fn onboard_signer(&mut self, account_id: AccountId) -> Result<(), Error> {
        // Use a batch call to onboard the new signer.
        let mut res = self
            .submit_and_watch(
                self.api
                    .call()
                    .utility()
                    .batch(vec![
                        // Onboard the new signer with a DID and CDD.
                        self.api
                            .call()
                            .identity()
                            .cdd_register_did_with_cdd(account_id, vec![], None)
                            .map_err(Error::from)?
                            .into(),
                        // Fund the new signer with some POLYX for fees.
                        self.api
                            .call()
                            .sudo()
                            .sudo(
                                self.api
                                    .call()
                                    .balances()
                                    .set_balance(
                                        account_id.into(),
                                        100_000_000_000, // Free balance: 100,000 POLYX
                                        0,               // Reserved balance
                                    )
                                    .map_err(Error::from)?
                                    .into(),
                            )
                            .map_err(Error::from)?
                            .into(),
                    ])
                    .map_err(Error::from)?,
            )
            .await?;

        // Check if the transaction was successful
        res.ok().await.map_err(Error::from)?;

        Ok(())
    }

    pub async fn get_did(&self) -> Result<Option<IdentityId>, JsValue> {
        let account_id = self.signer.account();
        let key_records = self
            .api
            .query()
            .identity()
            .key_records(account_id)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to query identity: {}", e)))?;

        match key_records {
            Some(KeyRecord::PrimaryKey(did) | KeyRecord::SecondaryKey(did)) => Ok(Some(did)),
            _ => Ok(None),
        }
    }
}

#[wasm_bindgen]
impl PolymeshSigner {
    /// Get the signer's account ID.
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> JsValue {
        let account_id = self.signer.account();
        JsValue::from_str(&account_id.to_string())
    }

    /// Set whether to finalize transactions.
    #[wasm_bindgen(setter)]
    pub fn set_finalize(&mut self, finalize: bool) {
        self.finalize = finalize;
    }

    /// Query the signer's Polymesh identity DID, if any.
    #[wasm_bindgen(js_name = identity)]
    pub async fn identity(&self) -> Result<JsValue, JsValue> {
        let did = self.get_did().await?;
        match did {
            Some(did) => Ok(identity_id_to_jsvalue(&did)),
            _ => Ok(JsValue::NULL),
        }
    }

    /// Register a DART account keys linking it to the signer's Polymesh identity.
    #[wasm_bindgen(js_name = registerAccount)]
    pub async fn register_account(
        &mut self,
        proof: &AccountRegistrationProof,
    ) -> Result<JsValue, JsValue> {
        let mut res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .register_accounts(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create register account call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit register account call: {}", e))
            })?;

        // Check if the transaction was successful
        res.ok()
            .await
            .map_err(|e| JsValue::from_str(&format!("Register account call failed: {}", e)))?;

        // Get the block hash.
        let hash = res.wait_in_block().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to wait for register account call to be included: {}",
                e
            ))
        })?;
        Ok(block_hash_to_jsvalue(hash))
    }

    /// Create a new confidential asset.
    #[wasm_bindgen(js_name = createAsset)]
    pub async fn create_asset(
        &mut self,
        mediators: Vec<EncryptionPublicKey>,
        auditors: Vec<EncryptionPublicKey>,
        data: JsValue,
    ) -> Result<CreateAssetResult, JsValue> {
        let mediators: BoundedBTreeSet<_, _> = mediators
            .into_iter()
            .map(|k| k.inner)
            .try_collect()
            .map_err(|e| JsValue::from_str(&format!("Too many asset mediators: {}", e)))?;
        let auditors: BoundedBTreeSet<_, _> =
            auditors
                .into_iter()
                .map(|k| k.inner)
                .try_collect()
                .map_err(|e| JsValue::from_str(&format!("Too many asset auditors: {}", e)))?;

        // Conver `data` from a JS string or byte array.
        let data = jsvalue_to_bytes(&data)?;

        let mut res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .create_asset(scale_convert(&mediators), scale_convert(&auditors), data)
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create create asset call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit create asset call: {}", e))
            })?;

        // Check if the transaction was successful
        res.ok()
            .await
            .map_err(|e| JsValue::from_str(&format!("Register account call failed: {}", e)))?;

        // Get the block hash.
        let block_hash = res
            .wait_in_block()
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to finalize create asset call: {}", e))
            })?
            .ok_or_else(|| {
                JsValue::from_str("Create asset transaction finalized without success")
            })?;

        // Process events to find the AssetCreated event.
        let events = res
            .events()
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to fetch events: {}", e)))?;
        if let Some(events) = events {
            for event in &events.0 {
                if let RuntimeEvent::ConfidentialAssets(ConfidentialAssetsEvent::AssetCreated {
                    asset_id,
                    ..
                }) = event.event
                {
                    // Return the Create Asset result.
                    let asset_state =
                        NativeAssetState::new_bounded(asset_id, &mediators, &auditors);
                    return Ok(CreateAssetResult {
                        asset_state: AssetState { inner: asset_state },
                        block_hash,
                    });
                }
            }
        }

        // Transactino must have failed if we reach here.
        Err(JsValue::from_str(
            "Create asset transaction finalized without AssetCreated event",
        ))
    }

    /// Register an account with a confidential asset.
    #[wasm_bindgen(js_name = registerAccountAsset)]
    pub async fn register_account_asset(
        &mut self,
        proof: &AccountAssetRegistrationProof,
    ) -> Result<AccountStateResult, JsValue> {
        // Wrap the proof in a batched proof.
        let proof = BatchedAccountAssetRegistrationProof::<()> {
            proofs: vec![proof.inner.clone()]
                .try_into()
                .map_err(|_| JsValue::from_str("Too many account asset registration proofs"))?,
        };

        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .register_account_assets(scale_convert(&proof))
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to create register account asset call: {}",
                            e
                        ))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to submit register account asset call: {}",
                    e
                ))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process register account asset transaction: {}",
                e
            ))
        })
    }

    /// Mint confidential asset tokens to an account.
    #[wasm_bindgen(js_name = mintAsset)]
    pub async fn mint_asset(
        &mut self,
        proof: &AssetMintingProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .mint_asset(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create mint asset call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to submit mint asset call: {}", e)))?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process register account asset transaction: {}",
                e
            ))
        })
    }

    /// Create a settlement from a settlement proof.
    #[wasm_bindgen(js_name = createSettlement)]
    pub async fn create_settlement(
        &mut self,
        proof: &SettlementProof,
    ) -> Result<CreateSettlementResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .create_settlement(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create settlement call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to submit settlement call: {}", e)))?;

        CreateSettlementResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process create settlement transaction: {}",
                e
            ))
        })
    }
}

/// Transaction results for created settlement.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct CreateSettlementResult {
    pub(crate) block_hash: BlockHash,
    pub(crate) settlement_ref: Option<SettlementRef>,
}

impl CreateSettlementResult {
    pub async fn from_tx(mut res: TransactionResults<Api>) -> Result<Self, Error> {
        // Check if the transaction was successful
        res.ok().await?;

        // Get the block hash.
        let block_hash = res
            .wait_in_block()
            .await?
            .ok_or_else(|| Error::other("Settlement transaction finalized without success"))?;

        // Process events to find the SettlementCreated event.
        let mut settlement_ref = None;
        let events = res.events().await?;
        if let Some(events) = events {
            for event in &events.0 {
                if let RuntimeEvent::ConfidentialAssets(
                    ConfidentialAssetsEvent::SettlementCreated {
                        settlement_ref: s_ref,
                        ..
                    },
                ) = &event.event
                {
                    settlement_ref = Some(scale_convert(s_ref));
                }
            }
        }

        Ok(CreateSettlementResult {
            block_hash,
            settlement_ref,
        })
    }
}

#[wasm_bindgen]
impl CreateSettlementResult {
    /// Get the block hash where the settlement was created.
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }

    /// Get the settlement reference, if available.
    #[wasm_bindgen(js_name = settlementRef)]
    pub fn settlement_ref(&self) -> JsValue {
        match &self.settlement_ref {
            Some(s_ref) => JsValue::from(settlement_ref_to_jsvalue(s_ref)),
            None => JsValue::NULL,
        }
    }
}

/// Transaction results for created confidential asset.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct CreateAssetResult {
    pub(crate) asset_state: AssetState,
    pub(crate) block_hash: BlockHash,
}

#[wasm_bindgen]
impl CreateAssetResult {
    /// Get the created asset state.
    #[wasm_bindgen(js_name = assetState)]
    pub fn asset_state(&self) -> AssetState {
        self.asset_state.clone()
    }

    /// Get the asset id.
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> u32 {
        self.asset_state.asset_id()
    }

    /// Get the block hash where the asset was created.
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }
}

/// Account state transaction results.
///
/// This is returned for transactions that create or modify account states.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct AccountStateResult {
    pub(crate) block_hash: BlockHash,
    pub(crate) leaf_index: u64,
}

impl AccountStateResult {
    pub async fn from_tx(mut res: TransactionResults<Api>) -> Result<Self, Error> {
        // Check if the transaction was successful
        res.ok().await?;

        // Get the block hash.
        let block_hash = res
            .wait_in_block()
            .await?
            .ok_or_else(|| Error::other("Account state transaction finalized without success"))?;

        // Process events to find the account state leaf index.
        let mut leaf_index = u64::MAX;
        let events = res.events().await?;
        if let Some(events) = events {
            for event in &events.0 {
                if let RuntimeEvent::ConfidentialAssets(
                    ConfidentialAssetsEvent::AccountStateLeafInserted {
                        leaf_index: index, ..
                    },
                ) = event.event
                {
                    leaf_index = index;
                }
            }
        }

        Ok(AccountStateResult {
            block_hash,
            leaf_index,
        })
    }
}

#[wasm_bindgen]
impl AccountStateResult {
    /// Get the block hash where the account state was modified.
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }

    /// Get the leaf index of the account state in the account curve tree, if available.
    #[wasm_bindgen(js_name = leafIndex)]
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}
