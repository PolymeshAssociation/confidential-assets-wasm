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
    MediatorAffirmationProof,
};
use crate::{block_hash_to_jsvalue, error::Error};
use crate::{
    keys::{AccountRegistrationProof, EncryptionPublicKey},
    AccountAssetRegistrationProof, ReceiverAffirmationProof, ReceiverClaimProof,
    SenderAffirmationProof, SenderCounterUpdateProof, SenderReversalProof, SettlementProof,
};
use crate::{scale_convert, AssetMintingProof};

/// A signer for submitting transactions to the Polymesh blockchain.
///
/// This type manages signing transactions and submitting them to the Polymesh network.
/// It uses a keypair derived from a seed phrase to sign transactions and associate them
/// with a blockchain account. The signer can be used to:
/// - Query the associated account identity (DID)
/// - Register confidential account keys
/// - Create and manage confidential assets
/// - Mint assets
/// - Create and affirm settlements
/// - Claim assets from settlements
///
/// # Finalization
/// By default, all transactions wait for finalization. This can be disabled via the `finalize` setter
/// for faster testing (transactions return as soon as they're included in a block).
///
/// # Example
/// ```javascript
/// const client = await PolymeshClient.connect("ws://localhost:9944");
/// let signer = client.newSigner("//TestAccount");
///
/// // Check the signer's account ID
/// console.log('Account:', signer.accountId());
///
/// // Query or create the identity
/// let did = await signer.identity();
/// if (did === null) {
///     await client.onboardSigner(signer);
///     did = await signer.identity();
/// }
/// console.log('DID:', did);
///
/// // Register confidential account keys
/// const keys = AccountKeys.fromSeed("my-seed");
/// const proof = keys.registerAccountProof(did);
/// await signer.registerAccount(proof);
/// ```
#[wasm_bindgen]
pub struct PolymeshSigner {
    pub(crate) signer: DefaultSigner,
    pub(crate) api: Api,
    pub(crate) finalize: bool,
}

impl PolymeshSigner {
    /// Create a new `PolymeshSigner` from a keypair, API connection, and finalization preference.
    ///
    /// # Arguments
    /// * `signer` - A `DefaultSigner` containing the keypair for signing transactions.
    /// * `api` - A reference to the `Api` connection to the Polymesh node.
    /// * `finalize` - Whether to wait for transaction finalization (true) or just block inclusion (false).
    ///
    /// # Returns
    /// A new `PolymeshSigner` instance ready to submit transactions.
    pub fn new(signer: DefaultSigner, api: &Api, finalize: bool) -> Self {
        PolymeshSigner {
            signer,
            api: api.clone(),
            finalize,
        }
    }

    /// Create a signer for the dev chain's Alice account.
    ///
    /// This is a convenience method for testing on development chains. Alice is a well-known
    /// development account with elevated privileges (e.g., sudo access for onboarding).
    ///
    /// # Arguments
    /// * `api` - A reference to the `Api` connection to the Polymesh node.
    /// * `finalize` - Whether to wait for transaction finalization.
    ///
    /// # Returns
    /// A `PolymeshSigner` for Alice's account.
    pub fn alice(api: &Api, finalize: bool) -> Self {
        Self::new(polymesh_api_client::dev::alice(), api, finalize)
    }

    /// Submit a call and watch for its inclusion in a block or finalization.
    ///
    /// Internal method that submits a transaction to the network and waits for confirmation.
    /// The method respects the `finalize` flag to determine whether to wait for finalization
    /// or just block inclusion.
    ///
    /// # Arguments
    /// * `call` - A `WrappedCall` representing the transaction to submit.
    ///
    /// # Returns
    /// Transaction results containing events and block information.
    ///
    /// # Errors
    /// * Throws if the transaction submission fails.
    /// * Throws if waiting for finalization/inclusion fails.
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

    /// Onboard a new account to the blockchain (development/test chains only).
    ///
    /// This is an internal utility method used by `PolymeshClient.onboardSigner()`.
    /// It performs the necessary steps to add a new account to a dev chain:
    /// 1. Registers a CDD (Customer Due Diligence) identity for the account
    /// 2. Funds the account with POLYX tokens for transaction fees
    ///
    /// This method uses sudo access and is only available on development chains.
    ///
    /// # Arguments
    /// * `account_id` - The blockchain account ID to onboard.
    ///
    /// # Returns
    /// OK if successful.
    ///
    /// # Errors
    /// * Throws if the account is already onboarded.
    /// * Throws if the sudo call fails (not available on production).
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

    /// Query the Polymesh identity (DID) associated with this signer's account.
    ///
    /// Internal utility method that checks the blockchain to see if this account
    /// has an associated Polymesh identity (DID). Returns `None` if the account
    /// hasn't been onboarded yet.
    ///
    /// # Returns
    /// `Some(did)` if the account has an identity, `None` otherwise.
    ///
    /// # Errors
    /// * Throws if the blockchain query fails.
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
    ///
    /// The account ID is the blockchain address derived from the signer's keypair.
    /// This is used to sign transactions and is distinct from the Polymesh identity (DID).
    ///
    /// # Returns
    /// A hexadecimal string representing the account ID (e.g., `"0x1234..."`).
    ///
    /// # Example
    /// ```javascript
    /// const signer = client.newSigner("//TestAccount");
    /// console.log('Account ID:', signer.accountId());
    /// ```
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> JsValue {
        let account_id = self.signer.account();
        JsValue::from_str(&account_id.to_string())
    }

    /// Set whether to finalize transactions.
    ///
    /// When set to `true` (default), transactions wait for finalization before returning.
    /// When set to `false`, transactions return after being included in a block (faster but weaker guarantees).
    ///
    /// # Arguments
    /// * `finalize` - Boolean value indicating whether to wait for finalization.
    ///
    /// # Example
    /// ```javascript
    /// signer.finalize = false; // Return after block inclusion (faster for testing)
    /// signer.finalize = true;  // Wait for finalization (safer for production)
    /// ```
    #[wasm_bindgen(setter)]
    pub fn set_finalize(&mut self, finalize: bool) {
        self.finalize = finalize;
    }

    /// Query the signer's Polymesh identity DID (Decentralized Identifier), if any.
    ///
    /// An account can be associated with a Polymesh identity (DID) which is used for
    /// legal/compliance identity on the blockchain. This method retrieves the DID associated
    /// with this signer's account. If no DID is found, `null` is returned.
    ///
    /// # Returns
    /// A hexadecimal string representing the DID (e.g., `"0x1234..."`), or `null` if not found.
    ///
    /// # Errors
    /// * Throws an error if querying the blockchain identity fails.
    ///
    /// # Example
    /// ```javascript
    /// let did = await signer.identity();
    /// if (did === null) {
    ///     console.log('Account has no identity, onboarding...');
    ///     await client.onboardSigner(signer);
    ///     did = await signer.identity();
    /// }
    /// console.log('Identity DID:', did);
    /// ```
    #[wasm_bindgen(js_name = identity)]
    pub async fn identity(&self) -> Result<JsValue, JsValue> {
        let did = self.get_did().await?;
        match did {
            Some(did) => Ok(identity_id_to_jsvalue(&did)),
            _ => Ok(JsValue::NULL),
        }
    }

    /// Register DART account keys and link them to this signer's Polymesh identity.
    ///
    /// This transaction registers the confidential account keys on-chain, creating a mapping
    /// between the account's public key and the signer's Polymesh identity (DID).
    /// After registration, the account can participate in confidential asset transactions.
    ///
    /// # Arguments
    /// * `proof` - An `AccountRegistrationProof` generated from `AccountKeys.registerAccountProof()`.
    ///
    /// # Returns
    /// A hexadecimal string representing the block hash where the transaction was included.
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails on-chain.
    /// * Throws an error if the transaction submission fails.
    /// * Throws an error if the transaction reverts on-chain.
    ///
    /// # Example
    /// ```javascript
    /// const keys = AccountKeys.fromSeed("my-seed-phrase");
    /// const proof = keys.registerAccountProof(myDid);
    /// const blockHash = await signer.registerAccount(proof);
    /// console.log('Account registered at block:', blockHash);
    /// ```
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

    /// Create a new confidential asset on-chain.
    ///
    /// This transaction creates a new DART (Decentralized Autonomous Reserved Token) confidential asset.
    /// The asset can be minted, transferred, and traded while maintaining confidentiality.
    /// Only the specified mediators and auditors can decrypt transaction details.
    ///
    /// # Arguments
    /// * `name` - The name of the asset (string).
    /// * `symbol` - The ticker symbol for the asset (string).
    /// * `decimals` - The number of decimal places for the asset (u8).
    /// * `mediators` - Array of `EncryptionPublicKey` objects for mediators. Mediators have special
    ///   privileges in the asset system. Pass an empty array if no mediators are needed.
    /// * `auditors` - Array of `EncryptionPublicKey` objects for auditors. Auditors can decrypt
    ///   and verify all transactions for this asset. Pass an empty array if no auditors are needed.
    /// * `data` - Asset metadata/descriptor. Accepts:
    ///   - String (ASCII text)
    ///   - Hex string with "0x" prefix (e.g., `"0x1234..."`)
    ///   - `Uint8Array` (raw bytes)
    ///
    /// # Returns
    /// A `CreateAssetResult` containing:
    /// - The created asset's state (ID, mediators, auditors)
    /// - The block hash where the asset was created
    ///
    /// # Errors
    /// * Throws an error if mediators or auditors arrays exceed system limits.
    /// * Throws an error if the transaction submission fails.
    /// * Throws an error if no `AssetCreated` event is found in transaction output.
    ///
    /// # Example
    /// ```javascript
    /// const issuer = client.newSigner("//TestIssuer");
    ///
    /// // Create asset with mediator and auditor
    /// const mediators = []; // No mediators
    /// const auditors = [mediatorEncryptionKey]; // Auditor key
    /// const result = await issuer.createAsset(mediators, auditors, "My Confidential Asset");
    ///
    /// const assetId = result.assetId();
    /// const assetState = result.assetState();
    /// console.log('Asset ID:', assetId);
    /// console.log('Created at block:', result.blockHash());
    /// ```
    #[wasm_bindgen(js_name = createAsset)]
    pub async fn create_asset(
        &mut self,
        name: String,
        symbol: String,
        decimals: u8,
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
                    .create_asset(
                        scale_convert(&name),
                        scale_convert(&symbol),
                        decimals,
                        scale_convert(&mediators),
                        scale_convert(&auditors),
                        data,
                    )
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
    ///
    /// This transaction registers a confidential account for a specific asset, allowing the account
    /// to participate in that asset's transactions (minting, transfers, etc.). Each account must be
    /// registered for each asset separately.
    ///
    /// # Arguments
    /// * `proof` - An `AccountAssetRegistrationProof` generated from
    ///   `AccountKeys.registerAccountAssetProof(assetId, did)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The leaf index where the account's state was inserted in the account curve tree
    /// - The block hash where the registration was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the asset doesn't exist.
    /// * Throws an error if the account is already registered for this asset.
    ///
    /// # Example
    /// ```javascript
    /// const accountKeys = AccountKeys.fromSeed("my-seed");
    /// const registration = accountKeys.registerAccountAssetProof(assetId, myDid);
    /// const proof = registration.getProof();
    ///
    /// const results = await issuer.registerAccountAsset(proof);
    /// console.log('Account registered at leaf index:', results.leafIndex());
    ///
    /// // Track the state locally
    /// const accountState = registration.getAccountAssetState();
    /// accountState.commitPendingState(results.leafIndex());
    /// ```
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
    ///
    /// This transaction creates new tokens of a confidential asset and adds them to the account's balance.
    /// Only authorized issuers (typically the asset creator) can mint. The minting amount is hidden
    /// within the zero-knowledge proof.
    ///
    /// # Arguments
    /// * `proof` - An `AssetMintingProof` generated from
    ///   `AccountAssetState.assetMintingProof(keys, path, amount)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the updated account state was inserted
    /// - The block hash where the minting was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the account is not registered for the asset.
    /// * Throws an error if proof generation failed (e.g., invalid path).
    ///
    /// # Example
    /// ```javascript
    /// const mintAmount = 1000000n; // BigInt for large amounts
    ///
    /// // Get the current leaf path
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const leafPath = await accountCurveTree.getLeafPathAndRoot(accountState.leafIndex());
    ///
    /// // Generate the minting proof
    /// const mintingProof = accountState.assetMintingProof(keys, leafPath, mintAmount);
    ///
    /// // Submit the minting transaction
    /// const results = await issuer.mintAsset(mintingProof);
    /// console.log('Minted at block:', results.blockHash());
    ///
    /// // Update the account state with the new leaf index
    /// accountState.commitPendingState(results.leafIndex());
    /// console.log('New balance:', accountState.balance());
    /// ```
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
            JsValue::from_str(&format!("Failed to process mint asset transaction: {}", e))
        })
    }

    /// Create a settlement from a settlement proof.
    ///
    /// This transaction creates a new settlement on-chain, which represents a proposed transfer
    /// (or multiple transfers across legs) of confidential assets. After creation, all parties
    /// involved (senders and receivers) must affirm their participation in the settlement,
    /// and then receivers can claim their assets.
    ///
    /// # Arguments
    /// * `proof` - A `SettlementProof` generated from `SettlementBuilder.build()`.
    ///
    /// # Returns
    /// A `CreateSettlementResult` containing:
    /// - The settlement reference (a unique identifier for this settlement)
    /// - The block hash where the settlement was created
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the proof references assets that don't exist.
    /// * Throws an error if transaction submission fails.
    /// * Throws an error if no `SettlementCreated` event is found.
    ///
    /// # Example
    /// ```javascript
    /// // Build the settlement proof
    /// const settlementBuilder = new SettlementBuilder("My settlement", blockNumber, assetTreeRoot);
    /// settlementBuilder.addAssetPath(assetId, assetPath);
    ///
    /// const legBuilder = new LegBuilder(senderKeys, receiverKeys, assetState, transferAmount);
    /// settlementBuilder.addLeg(legBuilder);
    ///
    /// const proof = settlementBuilder.build();
    ///
    /// // Create the settlement on-chain
    /// const result = await issuer.createSettlement(proof);
    /// const settlementRef = result.settlementRef();
    /// console.log('Settlement created:', settlementRef);
    ///
    /// // Later, retrieve and affirm the settlement legs
    /// const legs = await client.getSettlementLegs(settlementRef);
    /// ```
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

    /// Sender affirmation of a settlement leg.
    ///
    /// This transaction allows the sender (issuer/payer) of a settlement leg to affirm their
    /// commitment to the transfer. After a sender affirms, their confidential balance is deducted
    /// and the assets are held in a pending state until the receiver claims them.
    ///
    /// # Arguments
    /// * `proof` - A `SenderAffirmationProof` generated from
    ///   `AccountAssetState.senderAffirmProof(keys, path, settlementRef, legId, encryptedLeg, assetId, amount)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the sender's updated account state was inserted
    /// - The block hash where the affirmation was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the sender doesn't have sufficient balance.
    /// * Throws an error if the settlement or leg doesn't exist.
    ///
    /// # Example
    /// ```javascript
    /// // Retrieve the settlement legs
    /// const legs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = legs.getLeg(0);
    ///
    /// // Get the sender's current state and path
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const senderPath = await accountCurveTree.getLeafPathAndRoot(senderState.leafIndex());
    ///
    /// // Generate sender affirmation proof
    /// const proof = senderState.senderAffirmProof(
    ///     senderKeys,
    ///     senderPath,
    ///     settlementRef,
    ///     0,  // leg_id
    ///     encryptedLeg,
    ///     assetId,
    ///     null  // amount (pass null to use the amount from the encrypted leg)
    /// );
    ///
    /// // Submit affirmation
    /// const results = await signer.senderAffirmation(proof);
    /// senderState.commitPendingState(results.leafIndex());
    /// console.log('Sender affirmed at block:', results.blockHash());
    /// ```
    #[wasm_bindgen(js_name = senderAffirmation)]
    pub async fn sender_affirmation(
        &mut self,
        proof: &SenderAffirmationProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .sender_affirmation(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to create sender affirmation call: {}",
                            e
                        ))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit sender affirmation call: {}", e))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process sender affirmation transaction: {}",
                e
            ))
        })
    }

    /// Sender counter update.
    ///
    /// This transaction updates the sender's transaction counter. The counter is a monotonically
    /// increasing value used to prevent replay attacks and maintain transaction ordering for a sender.
    /// This is typically called after each settlement transaction by the sender.
    ///
    /// # Arguments
    /// * `proof` - A `SenderCounterUpdateProof` generated from
    ///   `AccountAssetState.senderCounterUpdateProof(keys, path, newCounter)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the updated account state was inserted
    /// - The block hash where the update was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the new counter is not greater than the current counter.
    /// * Throws an error if the account is not registered.
    ///
    /// # Example
    /// ```javascript
    /// // After a settlement, update the counter
    /// const newCounter = senderState.counter() + 1;
    ///
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const path = await accountCurveTree.getLeafPathAndRoot(senderState.leafIndex());
    ///
    /// const proof = senderState.senderCounterUpdateProof(
    ///     senderKeys,
    ///     path,
    ///     newCounter
    /// );
    ///
    /// const results = await signer.senderCounterUpdate(proof);
    /// senderState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = senderCounterUpdate)]
    pub async fn sender_counter_update(
        &mut self,
        proof: &SenderCounterUpdateProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .sender_update_counter(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to create sender update counter call: {}",
                            e
                        ))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to submit sender update counter call: {}",
                    e
                ))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process sender affirmation transaction: {}",
                e
            ))
        })
    }

    /// Sender revert/cancellation of a settlement leg.
    ///
    /// This transaction allows the sender to cancel/revert their affirmation of a settlement leg.
    /// The sender's balance is restored (the pending deduction is cancelled). This can only be done
    /// if the receiver hasn't claimed the assets yet.
    ///
    /// # Arguments
    /// * `proof` - A `SenderReversalProof` generated from
    ///   `AccountAssetState.senderReversalProof(keys, legData, path, counter)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the sender's restored account state was inserted
    /// - The block hash where the reversal was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the sender had not affirmed the leg.
    /// * Throws an error if the receiver has already claimed the assets.
    ///
    /// # Example
    /// ```javascript
    /// // Cancel a previously affirmed settlement
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const path = await accountCurveTree.getLeafPathAndRoot(senderState.leafIndex());
    ///
    /// const proof = senderState.senderReversalProof(
    ///     senderKeys,
    ///     decryptedLeg,
    ///     path,
    ///     senderState.counter()
    /// );
    ///
    /// const results = await signer.senderRevert(proof);
    /// senderState.commitPendingState(results.leafIndex());
    /// console.log('Sender reverted at block:', results.blockHash());
    /// ```
    #[wasm_bindgen(js_name = senderRevert)]
    pub async fn sender_revert(
        &mut self,
        proof: &SenderReversalProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .sender_revert(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create sender revert call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit sender revert call: {}", e))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process sender affirmation transaction: {}",
                e
            ))
        })
    }

    /// Receiver affirmation of a settlement leg.
    ///
    /// This transaction allows the receiver (beneficiary) of a settlement leg to affirm their
    /// commitment to receive the assets. After affirming, the receiver is ready to claim the
    /// assets. Both parties (sender and receiver) must affirm before assets can be claimed.
    ///
    /// # Arguments
    /// * `proof` - A `ReceiverAffirmationProof` generated from
    ///   `AccountAssetState.receiverAffirmProof(keys, path, settlementRef, legId, encryptedLeg, assetId, amount)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the receiver's updated account state was inserted
    /// - The block hash where the affirmation was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the receiver's account is not registered for the asset.
    /// * Throws an error if the settlement or leg doesn't exist.
    ///
    /// # Example
    /// ```javascript
    /// // Retrieve the settlement legs
    /// const legs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = legs.getLeg(0);
    ///
    /// // Get the receiver's current state and path
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const receiverPath = await accountCurveTree.getLeafPathAndRoot(receiverState.leafIndex());
    ///
    /// // Generate receiver affirmation proof
    /// const proof = receiverState.receiverAffirmProof(
    ///     receiverKeys,
    ///     receiverPath,
    ///     settlementRef,
    ///     0,  // leg_id
    ///     encryptedLeg,
    ///     assetId,
    ///     null  // amount (pass null to use the amount from the encrypted leg)
    /// );
    ///
    /// // Submit affirmation
    /// const results = await signer.receiverAffirmation(proof);
    /// receiverState.commitPendingState(results.leafIndex());
    /// console.log('Receiver affirmed at block:', results.blockHash());
    /// ```
    #[wasm_bindgen(js_name = receiverAffirmation)]
    pub async fn receiver_affirmation(
        &mut self,
        proof: &ReceiverAffirmationProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .receiver_affirmation(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to create receiver affirmation call: {}",
                            e
                        ))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to submit receiver affirmation call: {}",
                    e
                ))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process receiver affirmation transaction: {}",
                e
            ))
        })
    }

    /// Receiver claim of a settlement leg.
    ///
    /// This transaction allows the receiver to claim (finalize receipt of) the confidential assets
    /// from a settlement leg. After claiming, the receiver's balance increases by the transferred amount.
    /// Both the sender and receiver must have affirmed the settlement before claiming is possible.
    ///
    /// # Arguments
    /// * `proof` - A `ReceiverClaimProof` generated from
    ///   `AccountAssetState.receiverClaimProof(keys, path, settlementRef, legId, encryptedLeg, assetId, amount)`.
    ///
    /// # Returns
    /// An `AccountStateResult` containing:
    /// - The new leaf index where the receiver's account state with increased balance was inserted
    /// - The block hash where the claim was confirmed
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the sender has not affirmed the settlement.
    /// * Throws an error if the receiver has not affirmed the settlement.
    /// * Throws an error if the receiver has already claimed the assets.
    ///
    /// # Example
    /// ```javascript
    /// // After both sender and receiver have affirmed, receiver can claim
    /// // First, retrieve the settlement legs
    /// const legs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = legs.getLeg(0);
    ///
    /// // Get the receiver's current state and path
    /// const accountCurveTree = await client.getAccountCurveTree();
    /// const receiverPath = await accountCurveTree.getLeafPathAndRoot(receiverState.leafIndex());
    ///
    /// // Generate receiver claim proof
    /// const proof = receiverState.receiverClaimProof(
    ///     receiverKeys,
    ///     receiverPath,
    ///     settlementRef,
    ///     0,  // leg_id
    ///     encryptedLeg,
    ///     assetId,
    ///     null  // amount (pass null to use the amount from the encrypted leg)
    /// );
    ///
    /// // Submit the claim
    /// const results = await signer.receiverClaim(proof);
    /// receiverState.commitPendingState(results.leafIndex());
    /// console.log('Receiver claimed assets at block:', results.blockHash());
    /// console.log('New balance:', receiverState.balance());
    /// ```
    #[wasm_bindgen(js_name = receiverClaim)]
    pub async fn receiver_claim(
        &mut self,
        proof: &ReceiverClaimProof,
    ) -> Result<AccountStateResult, JsValue> {
        let res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .receiver_claim(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to create receiver claim call: {}", e))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to submit receiver claim call: {}", e))
            })?;

        AccountStateResult::from_tx(res).await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to process receiver claim transaction: {}",
                e
            ))
        })
    }

    /// Mediator affirmation of a settlement leg.
    ///
    /// This transaction allows a mediator to affirm their role in a settlement leg.
    ///
    /// # Arguments
    /// * `proof` - A `MediatorAffirmationProof` generated from
    ///   `mediatorKey.mediatorAffirmationProof(settlementRef, legId, encryptedLeg, accept, assetId, amount)`.
    ///
    /// # Returns
    /// A hexadecimal string representing the block hash where the affirmation was included.
    ///
    /// # Errors
    /// * Throws an error if the proof validation fails.
    /// * Throws an error if the settlement or leg doesn't exist.
    /// * Throws an error if the transaction submission fails.
    ///
    /// # Example
    /// ```javascript
    /// // As a mediator, affirm your role in the settlement leg
    /// const legs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = legs.getLeg(0);
    ///
    /// // Generate mediator affirmation proof
    /// const proof = mediatorKey.mediatorAffirmationProof(
    ///    settlementRef,
    ///    0,  // leg_id
    ///    encryptedLeg,
    ///    true,  // accept the leg
    ///    assetId,
    ///    null  // amount (pass null to use the amount from the encrypted leg)
    /// );
    ///
    /// // Submit the affirmation
    /// const blockHash = await signer.mediatorAffirmation(proof);
    /// console.log('Mediator affirmed at block:', blockHash);
    /// ```
    #[wasm_bindgen(js_name = mediatorAffirmation)]
    pub async fn mediator_affirmation(
        &mut self,
        proof: &MediatorAffirmationProof,
    ) -> Result<JsValue, JsValue> {
        let mut res = self
            .submit_and_watch(
                self.api
                    .call()
                    .confidential_assets()
                    .mediator_affirmation(scale_convert(&proof.inner))
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to create mediator affirmation call: {}",
                            e
                        ))
                    })?,
            )
            .await
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to submit mediator affirmation call: {}",
                    e
                ))
            })?;

        // Check if the transaction was successful
        res.ok()
            .await
            .map_err(|e| JsValue::from_str(&format!("Mediator affirmation call failed: {}", e)))?;

        // Get the block hash.
        let hash = res.wait_in_block().await.map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to wait for mediator affirmation call to be included: {}",
                e
            ))
        })?;
        Ok(block_hash_to_jsvalue(hash))
    }
}

/// Transaction results for creating a settlement on-chain.
///
/// This type contains the settlement reference and block hash resulting from a successful
/// settlement creation transaction. The settlement reference can be used to retrieve the
/// settlement details and legs from the blockchain.
///
/// # Example
/// ```javascript
/// const result = await issuer.createSettlement(proof);
/// const settlementRef = result.settlementRef();
/// const blockHash = result.blockHash();
///
/// // Use the settlement reference to retrieve legs
/// const legs = await client.getSettlementLegs(settlementRef);
/// ```
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
    ///
    /// # Returns
    /// A hexadecimal string representing the block hash (e.g., `"0x1234..."`).
    ///
    /// # Example
    /// ```javascript
    /// const blockHash = result.blockHash();
    /// console.log('Settlement created at block:', blockHash);
    /// ```
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }

    /// Get the settlement reference, if available.
    ///
    /// The settlement reference is a unique identifier for this settlement and is used to
    /// retrieve settlement legs and perform operations on the settlement.
    ///
    /// # Returns
    /// A hexadecimal string representing the settlement reference (e.g., `"0x1234..."`),
    /// or `null` if the settlement reference could not be determined.
    ///
    /// # Example
    /// ```javascript
    /// const settlementRef = result.settlementRef();
    /// if (settlementRef !== null) {
    ///     const legs = await client.getSettlementLegs(settlementRef);
    /// }
    /// ```
    #[wasm_bindgen(js_name = settlementRef)]
    pub fn settlement_ref(&self) -> JsValue {
        match &self.settlement_ref {
            Some(s_ref) => JsValue::from(settlement_ref_to_jsvalue(s_ref)),
            None => JsValue::NULL,
        }
    }
}

/// Transaction results for creating a confidential asset on-chain.
///
/// This type contains the created asset's state and the block hash where the asset was created.
/// The asset state includes the asset ID, mediators, and auditors configured for the asset.
///
/// # Example
/// ```javascript
/// const result = await issuer.createAsset([], [auditorKey], "My Asset");
/// const assetId = result.assetId();
/// const assetState = result.assetState();
/// const blockHash = result.blockHash();
///
/// console.log('Asset ID:', assetId);
/// console.log('Created at:', blockHash);
/// ```
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct CreateAssetResult {
    pub(crate) asset_state: AssetState,
    pub(crate) block_hash: BlockHash,
}

#[wasm_bindgen]
impl CreateAssetResult {
    /// Get the created asset state.
    ///
    /// # Returns
    /// An `AssetState` object containing the asset ID, mediators, and auditors.
    ///
    /// # Example
    /// ```javascript
    /// const assetState = result.assetState();
    /// console.log('Asset ID:', assetState.assetId());
    /// console.log('Mediators:', assetState.mediatorCount());
    /// console.log('Auditors:', assetState.auditorCount());
    /// ```
    #[wasm_bindgen(js_name = assetState)]
    pub fn asset_state(&self) -> AssetState {
        self.asset_state.clone()
    }

    /// Get the asset ID.
    ///
    /// # Returns
    /// The numeric ID of the created asset.
    ///
    /// # Example
    /// ```javascript
    /// const assetId = result.assetId();
    /// console.log('Created asset ID:', assetId);
    /// ```
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> u32 {
        self.asset_state.asset_id()
    }

    /// Get the block hash where the asset was created.
    ///
    /// # Returns
    /// A hexadecimal string representing the block hash (e.g., `"0x1234..."`).
    ///
    /// # Example
    /// ```javascript
    /// const blockHash = result.blockHash();
    /// console.log('Asset created at block:', blockHash);
    /// ```
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }
}

/// Account state transaction results.
///
/// This type is returned for transactions that create or modify account states (registration,
/// minting, affirmations, claims, etc.). It contains the leaf index where the account's new state
/// was inserted in the account curve tree and the block hash where the transaction was confirmed.
///
/// # Usage
/// After a successful account state transaction, use the `leafIndex()` to update your local
/// `AccountAssetState` by calling `commitPendingState(leafIndex)`. This ensures your local state
/// stays synchronized with the on-chain state.
///
/// # Example
/// ```javascript
/// const results = await issuer.mintAsset(proof);
/// const blockHash = results.blockHash();
/// const newLeafIndex = results.leafIndex();
///
/// // Update local state
/// accountState.commitPendingState(newLeafIndex);
///
/// console.log('Transaction confirmed at block:', blockHash);
/// console.log('New account leaf index:', newLeafIndex);
/// console.log('Updated balance:', accountState.balance());
/// ```
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
    ///
    /// # Returns
    /// A hexadecimal string representing the block hash (e.g., `"0x1234..."`).
    ///
    /// # Example
    /// ```javascript
    /// const blockHash = results.blockHash();
    /// console.log('Transaction included in block:', blockHash);
    /// ```
    #[wasm_bindgen(js_name = blockHash)]
    pub fn block_hash(&self) -> JsValue {
        block_hash_to_jsvalue(Some(self.block_hash))
    }

    /// Get the leaf index of the account state in the account curve tree.
    ///
    /// After a successful transaction, use this value to update your local `AccountAssetState`
    /// by calling `accountState.commitPendingState(leafIndex)`. This keeps your local state
    /// synchronized with the on-chain account tree.
    ///
    /// # Returns
    /// The leaf index as a `u64`.
    ///
    /// # Example
    /// ```javascript
    /// const results = await signer.registerAccountAsset(proof);
    /// const leafIndex = results.leafIndex();
    ///
    /// // Update local state
    /// accountState.commitPendingState(leafIndex);
    /// console.log('Account is now at leaf index:', leafIndex);
    /// ```
    #[wasm_bindgen(js_name = leafIndex)]
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}
