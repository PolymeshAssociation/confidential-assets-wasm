use bounded_collections::{BoundedBTreeSet, TryCollect};

use polymesh_api::{
    types::{
        polymesh_primitives::secondary_key::KeyRecord,
        runtime::{events::*, RuntimeEvent},
    },
    Api,
};
use polymesh_api_client::{AccountId, DefaultSigner, IdentityId, Signer};
use polymesh_dart::{AssetState as NativeAssetState, BatchedAccountAssetRegistrationProof};
use wasm_bindgen::prelude::*;

use crate::scale_convert;
use crate::{asset::AssetState, identity_id_to_jsvalue};
use crate::{block_hash_to_jsvalue, error::Error};
use crate::{
    keys::{AccountRegistrationProof, EncryptionPublicKey},
    AccountAssetRegistrationProof,
};

/// Polymesh Signer.
#[wasm_bindgen]
pub struct PolymeshSigner {
    pub(crate) signer: DefaultSigner,
    pub(crate) api: Api,
}

impl PolymeshSigner {
    pub fn new(signer: DefaultSigner, api: &Api) -> Self {
        PolymeshSigner {
            signer,
            api: api.clone(),
        }
    }

    pub fn alice(api: &Api) -> Self {
        Self::new(polymesh_api_client::dev::alice(), api)
    }

    pub(crate) async fn onboard_signer(&mut self, account_id: AccountId) -> Result<(), Error> {
        // Use a batch call to onboard the new signer.
        let mut res = self
            .api
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
            .map_err(Error::from)?
            .submit_and_watch(&mut self.signer)
            .await
            .map_err(Error::from)?;

        // Wait for the batch call to be finalized
        res.wait_finalized().await?;

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
            .api
            .call()
            .confidential_assets()
            .register_accounts(scale_convert(&proof.inner))
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to create register account call: {}", e))
            })?
            .submit_and_watch(&mut self.signer)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit register account call: {}", e))
            })?;

        // Check if the transaction was successful
        res.ok()
            .await
            .map_err(|e| JsValue::from_str(&format!("Register account call failed: {}", e)))?;

        // Wait for the call to be finalized
        let hash = res.wait_finalized().await.map_err(|e| {
            JsValue::from_str(&format!("Failed to finalize register account call: {}", e))
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
    ) -> Result<AssetState, JsValue> {
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
        let data = if let Some(js_str) = data.as_string() {
            js_str.into_bytes()
        } else {
            js_sys::Uint8Array::from(data).to_vec()
        };

        let mut res = self
            .api
            .call()
            .confidential_assets()
            .create_asset(scale_convert(&mediators), scale_convert(&auditors), data)
            .map_err(|e| JsValue::from_str(&format!("Failed to create create asset call: {}", e)))?
            .submit_and_watch(&mut self.signer)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit create asset call: {}", e))
            })?;

        // Check if the transaction was successful
        res.ok()
            .await
            .map_err(|e| JsValue::from_str(&format!("Register account call failed: {}", e)))?;

        // Wait for the call to be finalized and get the asset ID from the event.
        res.wait_finalized().await.map_err(|e| {
            JsValue::from_str(&format!("Failed to finalize create asset call: {}", e))
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
                    // Return the new AssetState
                    let asset_state =
                        NativeAssetState::new_bounded(asset_id, &mediators, &auditors);
                    return Ok(AssetState { inner: asset_state });
                }
            }
        }

        // Transactino must have failed if we reach here.
        Err(JsValue::from_str(
            "Create asset transaction finalized without AssetCreated event",
        ))
    }

    /// Register an account with a confidential asset.
    #[wasm_bindgen(js_name = registerAccountAssets)]
    pub async fn register_account_assets(
        &mut self,
        proof: Vec<AccountAssetRegistrationProof>,
    ) -> Result<JsValue, JsValue> {
        // Wrap the proof in a batched proof.
        let proof = BatchedAccountAssetRegistrationProof::<()> {
            proofs: proof
                .into_iter()
                .map(|p| p.inner)
                .try_collect()
                .map_err(|e| {
                    JsValue::from_str(&format!("Too many account asset registrations: {}", e))
                })?,
        };

        let mut res = self
            .api
            .call()
            .confidential_assets()
            .register_account_assets(scale_convert(&proof))
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to create register account asset call: {}",
                    e
                ))
            })?
            .submit_and_watch(&mut self.signer)
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to submit register account asset call: {}",
                    e
                ))
            })?;

        // Check if the transaction was successful
        res.ok().await.map_err(|e| {
            JsValue::from_str(&format!("Register account asset call failed: {}", e))
        })?;

        // Wait for the call to be finalized
        let hash = res.wait_finalized().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to finalize register account asset call: {}",
                e
            ))
        })?;

        Ok(block_hash_to_jsvalue(hash))
    }
}
