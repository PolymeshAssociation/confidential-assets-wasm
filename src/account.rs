use codec::{Decode, Encode};
use polymesh_dart::{
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountAssetState as NativeAccountAssetState, AccountState as NativeAccountState,
    AssetMintingProof as NativeAssetMintingProof, LegId, LegRef,
    ReceiverAffirmationProof as NativeReceiverAffirmationProof,
    ReceiverClaimProof as NativeReceiverClaimProof,
    SenderAffirmationProof as NativeSenderAffirmationProof,
    SenderCounterUpdateProof as NativeSenderCounterUpdateProof,
    SenderReversalProof as NativeSenderReversalProof,
};
use polymesh_dart::{AssetId, LegRole};
use wasm_bindgen::prelude::*;

use crate::{
    balance_to_jsvalue, jsvalue_to_balance, jsvalue_to_settlement_ref, AccountKeys,
    AccountLeafPathAndRoot, ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof,
    SenderCounterUpdateProof, SenderReversalProof, SettlementLegEncrypted,
};

/// Manages the confidential account state for a specific asset.
///
/// This type tracks an account's confidential balance for a particular asset, including
/// pending transaction states. It's used to generate proofs for minting, settlements,
/// and other confidential asset operations. The state must be kept in sync with the
/// on-chain account tree by committing pending states after successful transactions.
///
/// # Example
/// ```javascript
/// // Get account asset state from registration
/// const registration = issuerKeys.registerAccountAssetProof(assetId, issuerDid);
/// const accountState = registration.getAccountAssetState();
///
/// // After a successful transaction, commit the new state
/// const results = await issuer.registerAccountAsset(registration.getProof());
/// accountState.commitPendingState(results.leafIndex());
///
/// // Check the balance
/// console.log('Balance:', accountState.balance());
/// ```
#[wasm_bindgen]
#[derive(Clone, Debug, Encode, Decode)]
pub struct AccountAssetState {
    pub(crate) inner: NativeAccountAssetState,
    pub(crate) leaf_index: u64,
}

impl AccountAssetState {
    pub fn new(inner: NativeAccountAssetState) -> Self {
        AccountAssetState {
            inner,
            leaf_index: u64::MAX,
        }
    }
}

#[wasm_bindgen]
impl AccountAssetState {
    /// Serializes the account asset state to a SCALE-encoded byte array.
    ///
    /// This allows you to store the state off-chain and restore it later.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded state.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = accountState.toBytes();
    /// // Store bytes in local storage or a database
    /// localStorage.setItem('accountState', JSON.stringify(Array.from(bytes)));
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    /// Deserializes account asset state from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded account asset state data.
    ///
    /// # Returns
    /// The deserialized `AccountAssetState` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const storedBytes = JSON.parse(localStorage.getItem('accountState'));
    /// const accountState = AccountAssetState.fromBytes(new Uint8Array(storedBytes));
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountAssetState, JsValue> {
        let state = AccountAssetState::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode account asset state: {}", e))
        })?;
        Ok(state)
    }

    /// Gets the asset ID associated with this account state.
    ///
    /// # Returns
    /// The numeric asset ID (as a number).
    ///
    /// # Example
    /// ```javascript
    /// const assetId = accountState.assetId();
    /// console.log('Asset ID:', assetId);
    /// ```
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id()
    }

    /// Gets the leaf index of this account in the account curve tree.
    ///
    /// The leaf index is assigned when an account is registered for an asset and is
    /// needed to retrieve the account's curve tree path for proof generation.
    ///
    /// # Returns
    /// The leaf index as a `bigint`. Returns `u64::MAX` if not yet set.
    ///
    /// # Example
    /// ```javascript
    /// const leafIndex = accountState.leafIndex();
    /// const path = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    /// ```
    #[wasm_bindgen(js_name = leafIndex)]
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Commits a pending state change to the current state and updates the leaf index.
    ///
    /// After a successful transaction that modifies the account state (e.g., minting,
    /// affirming a settlement), you must call this method with the new leaf index
    /// from the transaction results. This updates the local state to match the on-chain state.
    ///
    /// # Arguments
    /// * `leaf_index` - The new leaf index from the transaction results. Pass `u64::MAX`
    ///   (JavaScript: `18446744073709551615n`) to discard pending state without committing.
    ///
    /// # Example
    /// ```javascript
    /// // Generate and submit a minting proof
    /// const mintingProof = accountState.assetMintingProof(keys, path, 1000n);
    /// const results = await signer.mintAsset(mintingProof);
    ///
    /// // Commit the pending state with the new leaf index
    /// accountState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = commitPendingState)]
    pub fn commit_pending_state(&mut self, leaf_index: u64) {
        if leaf_index == u64::MAX {
            // Remove pending state without committing
            self.inner.pending_state = None;
        } else {
            self.inner
                .commit_pending_state()
                .expect("Failed to commit pending state");
            self.leaf_index = leaf_index;
        }
    }

    /// Checks if there is a pending state change that hasn't been committed yet.
    ///
    /// A pending state exists after generating a proof but before committing the
    /// transaction results. This is useful to prevent generating multiple proofs
    /// before committing the first one.
    ///
    /// # Returns
    /// `true` if there's a pending state change, `false` otherwise.
    ///
    /// # Example
    /// ```javascript
    /// if (accountState.hasPendingState()) {
    ///   console.log('Warning: Pending state exists. Commit or discard before generating new proofs.');
    /// }
    /// ```
    #[wasm_bindgen(js_name = hasPendingState)]
    pub fn has_pending_state(&self) -> bool {
        self.inner.pending_state.is_some()
    }

    /// Gets the current confidential balance for this account asset.
    ///
    /// # Returns
    /// The balance as a `bigint`.
    ///
    /// # Example
    /// ```javascript
    /// const balance = accountState.balance();
    /// console.log('Current balance:', balance);
    /// ```
    #[wasm_bindgen(js_name = balance)]
    pub fn balance(&self) -> JsValue {
        balance_to_jsvalue(self.inner.current_state.balance)
    }

    /// Exports the account asset state as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the state.
    ///
    /// # Errors
    /// * Throws an error if serialization fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Account State:', accountState.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }

    /// Generates a zero-knowledge proof for minting new assets to this account.
    ///
    /// This proof demonstrates that the account holder has the authority to mint
    /// assets without revealing the amount or account details. The proof must be
    /// submitted via `PolymeshSigner.mintAsset()`.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root, obtained
    ///   from `AccountCurveTree.getLeafPathAndRoot()`.
    /// * `amount` - The amount to mint. Accepts:
    ///   - JavaScript number (e.g., `1000`)
    ///   - JavaScript BigInt (e.g., `1000n`)
    ///   - Decimal string (e.g., `"1000"`)
    ///   - Hex string with 0x prefix (e.g., `"0x3e8"`)
    ///
    /// # Returns
    /// An `AssetMintingProof` that can be submitted to the blockchain.
    ///
    /// # Errors
    /// * Throws an error if the proof generation fails.
    /// * Throws an error if the amount format is invalid.
    ///
    /// # Example
    /// ```javascript
    /// const leafIndex = issuerAccountState.leafIndex();
    /// const path = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    /// const mintAmount = 1000000n;
    ///
    /// const mintingProof = issuerAccountState.assetMintingProof(
    ///   issuerKeys,
    ///   path,
    ///   mintAmount
    /// );
    ///
    /// const results = await issuer.mintAsset(mintingProof);
    /// issuerAccountState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = assetMintingProof)]
    pub fn asset_minting_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        amount: JsValue,
    ) -> Result<AssetMintingProof, JsValue> {
        let amount = jsvalue_to_balance(&amount)?;
        let mut rng = rand::rngs::OsRng;
        let account = &keys.inner.acct;

        let proof =
            NativeAssetMintingProof::new(&mut rng, account, &mut self.inner, &path.path, amount)
                .map_err(|e| {
                    JsValue::from_str(&format!("Failed to generate asset minting proof: {}", e))
                })?;

        Ok(AssetMintingProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for the sender to affirm their participation in a settlement leg.
    ///
    /// As the sender in a confidential asset transfer, you must affirm the settlement leg
    /// by proving you have sufficient balance without revealing the amount. This proof
    /// decrements your balance by the transfer amount and locks it for the settlement.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root.
    /// * `settlement_ref` - The settlement reference ID. Accepts:
    ///   - Hex string with or without "0x" prefix (e.g., "0x1234...")
    ///   - 32-byte `Uint8Array`
    /// * `leg_id` - The leg ID within the settlement (typically `0` for the first leg).
    /// * `leg_enc` - The encrypted settlement leg containing transfer details.
    /// * `asset_id` - The asset ID being transferred (must match the leg's asset).
    /// * `amount` - Optional amount for validation. If provided, verifies it matches the
    ///   encrypted leg amount. Pass `null` or `undefined` to skip validation. Accepts:
    ///   - JavaScript number (e.g., `1000`)
    ///   - JavaScript BigInt (e.g., `1000n`)
    ///   - Decimal string (e.g., `"1000"`)
    ///   - Hex string with 0x prefix (e.g., `"0x3e8"`)
    ///
    /// # Returns
    /// A `SenderAffirmationProof` that can be submitted via `PolymeshSigner.senderAffirmation()`.
    ///
    /// # Errors
    /// * Throws an error if the encrypted leg cannot be decrypted with the provided keys.
    /// * Throws an error if the asset ID doesn't match the leg's asset ID.
    /// * Throws an error if the amount is provided and doesn't match the leg amount.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const settlementLegs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = settlementLegs.getLeg(0);
    /// const leafIndex = senderAccountState.leafIndex();
    /// const path = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    ///
    /// const senderProof = senderAccountState.senderAffirmProof(
    ///   senderKeys,
    ///   path,
    ///   settlementRef,
    ///   0,  // leg_id
    ///   encryptedLeg,
    ///   assetId,
    ///   null  // Let it use the amount from the encrypted leg
    /// );
    ///
    /// const results = await sender.senderAffirmation(senderProof);
    /// senderAccountState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = senderAffirmProof)]
    pub fn sender_affirm_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<SenderAffirmationProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let keys = &keys.inner;
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt settlement leg: {}", e)))?;
        // Verify asset id matches.
        if leg.asset_id != asset_id {
            return Err(JsValue::from_str("Settlement leg asset ID does not match"));
        }
        // Verify amount matches if provided.
        if !amount.is_null_or_undefined() {
            let amount = jsvalue_to_balance(&amount)?;
            if leg.amount != amount {
                return Err(JsValue::from_str(
                    "Settlement leg amount does not match provided amount",
                ));
            }
        }
        let amount = leg.amount;

        let proof = NativeSenderAffirmationProof::new(
            &mut rng,
            &keys.acct,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            &mut self.inner,
            &path.path,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to generate sender affirmation proof: {}",
                e
            ))
        })?;

        Ok(SenderAffirmationProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for the sender to update their transaction counter
    /// without transferring assets.
    ///
    /// This is used to increment the sender's transaction counter for a settlement leg
    /// without actually transferring the locked assets. This can be useful in certain
    /// settlement workflows where the counter needs to be updated separately.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root.
    /// * `settlement_ref` - The settlement reference ID (as a `bigint` or number).
    /// * `leg_id` - The leg ID within the settlement.
    /// * `leg_enc` - The encrypted settlement leg.
    /// * `asset_id` - The asset ID (must match the leg's asset).
    /// * `amount` - Optional amount for validation. Pass `null` or `undefined` to skip.
    ///
    /// # Returns
    /// A `SenderCounterUpdateProof` that can be submitted to the blockchain.
    ///
    /// # Errors
    /// * Throws an error if the encrypted leg cannot be decrypted.
    /// * Throws an error if the asset ID doesn't match.
    /// * Throws an error if the amount is provided and doesn't match.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const proof = accountState.senderCounterUpdateProof(
    ///   keys,
    ///   path,
    ///   settlementRef,
    ///   0,
    ///   encryptedLeg,
    ///   assetId,
    ///   null
    /// );
    /// ```
    #[wasm_bindgen(js_name = senderCounterUpdateProof)]
    pub fn sender_counter_update_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<SenderCounterUpdateProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let keys = &keys.inner;
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt settlement leg: {}", e)))?;

        // Verify asset id matches.
        if leg.asset_id != asset_id {
            return Err(JsValue::from_str("Settlement leg asset id does not match"));
        }
        // Verify amount matches if provided.
        if !amount.is_null_or_undefined() {
            let amount = jsvalue_to_balance(&amount)?;
            if leg.amount != amount {
                return Err(JsValue::from_str("Settlement leg amount does not match"));
            }
        }

        let proof = NativeSenderCounterUpdateProof::new(
            &mut rng,
            &keys.acct,
            &leg_ref,
            &leg_enc,
            &leg_enc_rand,
            &mut self.inner,
            &path.path,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to generate sender counter update proof: {}",
                e
            ))
        })?;

        Ok(SenderCounterUpdateProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for the sender to revert (cancel) their affirmation
    /// of a settlement leg.
    ///
    /// If a sender has affirmed a settlement leg but wants to cancel before the receiver
    /// claims the assets, they can generate a revert proof. This unlocks the previously
    /// locked assets and returns them to the sender's available balance.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root.
    /// * `settlement_ref` - The settlement reference ID (as a `bigint` or number).
    /// * `leg_id` - The leg ID within the settlement.
    /// * `leg_enc` - The encrypted settlement leg.
    /// * `asset_id` - The asset ID being reverted (must match the leg's asset).
    /// * `amount` - Optional amount for validation. Pass `null` or `undefined` to skip.
    ///
    /// # Returns
    /// A `SenderReversalProof` that can be submitted to the blockchain.
    ///
    /// # Errors
    /// * Throws an error if the encrypted leg cannot be decrypted.
    /// * Throws an error if the asset ID doesn't match.
    /// * Throws an error if the amount is provided and doesn't match.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const revertProof = senderAccountState.senderRevertProof(
    ///   senderKeys,
    ///   path,
    ///   settlementRef,
    ///   0,
    ///   encryptedLeg,
    ///   assetId,
    ///   null
    /// );
    ///
    /// // Submit the revert proof to cancel the sender's affirmation
    /// const results = await sender.senderReversal(revertProof);
    /// senderAccountState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = senderRevertProof)]
    pub fn sender_revert_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<SenderReversalProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let keys = &keys.inner;
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt settlement leg: {}", e)))?;

        // Verify asset id matches.
        if leg.asset_id != asset_id {
            return Err(JsValue::from_str("Settlement leg asset id does not match"));
        }
        // Verify amount matches if provided.
        if !amount.is_null_or_undefined() {
            let amount = jsvalue_to_balance(&amount)?;
            if leg.amount != amount {
                return Err(JsValue::from_str("Settlement leg amount does not match"));
            }
        }
        let amount = leg.amount;

        let proof = NativeSenderReversalProof::new(
            &mut rng,
            &keys.acct,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            &mut self.inner,
            &path.path,
        )
        .map_err(|e| {
            JsValue::from_str(&format!("Failed to generate sender revert proof: {}", e))
        })?;

        Ok(SenderReversalProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for the receiver to affirm their participation
    /// in a settlement leg.
    ///
    /// As the receiver in a confidential asset transfer, you must affirm the settlement leg
    /// by proving you can receive the assets. This doesn't immediately credit your balance;
    /// you must call `receiverClaimProof()` after both parties have affirmed to actually
    /// claim the transferred assets.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root.
    /// * `settlement_ref` - The settlement reference ID (as a `bigint` or number).
    /// * `leg_id` - The leg ID within the settlement.
    /// * `leg_enc` - The encrypted settlement leg containing transfer details.
    /// * `asset_id` - The asset ID being received (must match the leg's asset).
    /// * `amount` - Optional amount for validation. Pass `null` or `undefined` to skip.
    ///
    /// # Returns
    /// A `ReceiverAffirmationProof` that can be submitted via `PolymeshSigner.receiverAffirmation()`.
    ///
    /// # Errors
    /// * Throws an error if the encrypted leg cannot be decrypted with the provided keys.
    /// * Throws an error if the asset ID doesn't match the leg's asset ID.
    /// * Throws an error if the amount is provided and doesn't match the leg amount.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const settlementLegs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = settlementLegs.getLeg(0);
    /// const leafIndex = receiverAccountState.leafIndex();
    /// const path = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    ///
    /// const receiverProof = receiverAccountState.receiverAffirmProof(
    ///   receiverKeys,
    ///   path,
    ///   settlementRef,
    ///   0,
    ///   encryptedLeg,
    ///   assetId,
    ///   null
    /// );
    ///
    /// const results = await receiver.receiverAffirmation(receiverProof);
    /// receiverAccountState.commitPendingState(results.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = receiverAffirmProof)]
    pub fn receiver_affirm_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<ReceiverAffirmationProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let keys = &keys.inner;
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Receiver, keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt settlement leg: {}", e)))?;

        // Verify asset id matches.
        if leg.asset_id != asset_id {
            return Err(JsValue::from_str("Settlement leg asset id does not match"));
        }
        // Verify amount matches if provided.
        if !amount.is_null_or_undefined() {
            let amount = jsvalue_to_balance(&amount)?;
            if leg.amount != amount {
                return Err(JsValue::from_str("Settlement leg amount does not match"));
            }
        }

        let proof = NativeReceiverAffirmationProof::new(
            &mut rng,
            &keys.acct,
            &leg_ref,
            &leg_enc,
            &leg_enc_rand,
            &mut self.inner,
            &path.path,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to generate receiver affirmation proof: {}",
                e
            ))
        })?;

        Ok(ReceiverAffirmationProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for the receiver to claim assets from an affirmed
    /// settlement leg.
    ///
    /// After both the sender and receiver have affirmed a settlement leg, the receiver must
    /// generate and submit a claim proof to actually receive the transferred assets into their
    /// confidential balance. This is the final step in a confidential asset transfer.
    ///
    /// # Arguments
    /// * `keys` - The account keys proving ownership of this account.
    /// * `path` - The curve tree path from the account leaf to the tree root.
    /// * `settlement_ref` - The settlement reference ID (as a `bigint` or number).
    /// * `leg_id` - The leg ID within the settlement.
    /// * `leg_enc` - The encrypted settlement leg containing transfer details.
    /// * `asset_id` - The asset ID being claimed (must match the leg's asset).
    /// * `amount` - Optional amount for validation. Pass `null` or `undefined` to skip.
    ///
    /// # Returns
    /// A `ReceiverClaimProof` that can be submitted via `PolymeshSigner.receiverClaim()`.
    ///
    /// # Errors
    /// * Throws an error if the encrypted leg cannot be decrypted with the provided keys.
    /// * Throws an error if the asset ID doesn't match the leg's asset ID.
    /// * Throws an error if the amount is provided and doesn't match the leg amount.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// // After both parties have affirmed, the receiver can claim
    /// const settlementLegs = await client.getSettlementLegs(settlementRef);
    /// const encryptedLeg = settlementLegs.getLeg(0);
    /// const leafIndex = receiverAccountState.leafIndex();
    /// const path = await accountCurveTree.getLeafPathAndRoot(leafIndex);
    ///
    /// const claimProof = receiverAccountState.receiverClaimProof(
    ///   receiverKeys,
    ///   path,
    ///   settlementRef,
    ///   0,
    ///   encryptedLeg,
    ///   assetId,
    ///   null
    /// );
    ///
    /// const results = await receiver.receiverClaim(claimProof);
    /// receiverAccountState.commitPendingState(results.leafIndex());
    ///
    /// // The receiver's balance is now updated with the transferred amount
    /// console.log('New balance:', receiverAccountState.balance());
    /// ```
    #[wasm_bindgen(js_name = receiverClaimProof)]
    pub fn receiver_claim_proof(
        &mut self,
        keys: &AccountKeys,
        path: &AccountLeafPathAndRoot,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<ReceiverClaimProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let keys = &keys.inner;
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Receiver, keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt settlement leg: {}", e)))?;

        // Verify asset id matches.
        if leg.asset_id != asset_id {
            return Err(JsValue::from_str("Settlement leg asset id does not match"));
        }
        // Verify amount matches if provided.
        if !amount.is_null_or_undefined() {
            let amount = jsvalue_to_balance(&amount)?;
            if leg.amount != amount {
                return Err(JsValue::from_str("Settlement leg amount does not match"));
            }
        }
        let amount = leg.amount;

        let proof = NativeReceiverClaimProof::new(
            &mut rng,
            &keys.acct,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            &mut self.inner,
            &path.path,
        )
        .map_err(|e| {
            JsValue::from_str(&format!("Failed to generate receiver claim proof: {}", e))
        })?;

        Ok(ReceiverClaimProof { inner: proof })
    }
}

/// Represents the on-chain commitment value stored in the account curve tree.
///
/// This is a read-only snapshot of an account's state at a specific point in time,
/// containing the asset ID, balance, and transaction counter. Unlike `AccountAssetState`,
/// this type doesn't track pending changes and is primarily used for verification
/// and debugging purposes.
///
/// # Example
/// ```javascript
/// // Typically obtained from on-chain queries or deserialization
/// const accountState = AccountState.fromBytes(stateBytes);
/// console.log('Asset ID:', accountState.assetId());
/// console.log('Balance:', accountState.balance());
/// console.log('Counter:', accountState.counter());
/// ```
#[wasm_bindgen]
pub struct AccountState {
    pub(crate) inner: NativeAccountState,
}

impl AccountState {
    pub fn new(inner: NativeAccountState) -> Self {
        AccountState { inner }
    }
}

#[wasm_bindgen]
impl AccountState {
    /// Serializes the account state to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded state.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = accountState.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes account state from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded account state data.
    ///
    /// # Returns
    /// The deserialized `AccountState` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const accountState = AccountState.fromBytes(encodedBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountState, JsValue> {
        let inner = NativeAccountState::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode account state: {}", e)))?;
        Ok(AccountState { inner })
    }

    /// Gets the asset ID associated with this account state.
    ///
    /// # Returns
    /// The numeric asset ID.
    ///
    /// # Example
    /// ```javascript
    /// const assetId = accountState.assetId();
    /// ```
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id
    }

    /// Gets the confidential balance for this account.
    ///
    /// # Returns
    /// The balance as a `bigint`.
    ///
    /// # Example
    /// ```javascript
    /// const balance = accountState.balance();
    /// ```
    #[wasm_bindgen(js_name = balance)]
    pub fn balance(&self) -> JsValue {
        balance_to_jsvalue(self.inner.balance)
    }

    /// Gets the pending transaction counter for this account.
    ///
    /// The counter increments with each transaction to prevent replay attacks and
    /// ensure transaction ordering.
    ///
    /// # Returns
    /// The counter value as a `bigint`.
    ///
    /// # Example
    /// ```javascript
    /// const counter = accountState.counter();
    /// ```
    #[wasm_bindgen(js_name = counter)]
    pub fn counter(&self) -> u64 {
        self.inner.counter
    }

    /// Exports the account state as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the state.
    ///
    /// # Errors
    /// * Throws an error if serialization fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('State:', accountState.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// A batched collection of account asset registration proofs for multiple accounts.
///
/// This allows registering multiple accounts for an asset in a single transaction,
/// which is more efficient than registering each account individually.
///
/// # Example
/// ```javascript
/// // Typically created from individual registration proofs
/// const batchedProof = registration.getBatchedProof();
/// const bytes = batchedProof.toBytes();
/// ```
#[wasm_bindgen]
pub struct BatchedAccountAssetRegistrationProof {
    pub(crate) proofs: Vec<NativeAccountAssetRegistrationProof>,
}

#[wasm_bindgen]
impl BatchedAccountAssetRegistrationProof {
    /// Serializes the batched proof to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded batched proof.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = batchedProof.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proofs.encode()
    }

    /// Deserializes a batched proof from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded batched proof data.
    ///
    /// # Returns
    /// The deserialized `BatchedAccountAssetRegistrationProof` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const batchedProof = BatchedAccountAssetRegistrationProof.fromBytes(bytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<BatchedAccountAssetRegistrationProof, JsValue> {
        let proofs =
            Vec::<NativeAccountAssetRegistrationProof>::decode(&mut &bytes[..]).map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to decode batched registration proof: {}",
                    e
                ))
            })?;
        Ok(BatchedAccountAssetRegistrationProof { proofs })
    }
}

/// A zero-knowledge proof that registers an account for a specific confidential asset.
///
/// This proof demonstrates that the account holder has the authority to participate
/// in transactions for the specified asset without revealing their identity or other
/// sensitive information. The proof must be submitted via `PolymeshSigner.registerAccountAsset()`.
///
/// # Example
/// ```javascript
/// // Generated from AccountKeys
/// const registration = accountKeys.registerAccountAssetProof(assetId, did);
/// const proof = registration.getProof();
///
/// // Submit to blockchain
/// const results = await signer.registerAccountAsset(proof);
/// ```
#[wasm_bindgen]
pub struct AccountAssetRegistrationProof {
    pub(crate) inner: NativeAccountAssetRegistrationProof,
}

#[wasm_bindgen]
impl AccountAssetRegistrationProof {
    /// Serializes the proof to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded proof.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = proof.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes a proof from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded proof data.
    ///
    /// # Returns
    /// The deserialized `AccountAssetRegistrationProof` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const proof = AccountAssetRegistrationProof.fromBytes(bytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountAssetRegistrationProof, JsValue> {
        let inner = NativeAccountAssetRegistrationProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode registration proof: {}", e))
        })?;
        Ok(AccountAssetRegistrationProof { inner })
    }

    /// Exports the proof as a hexadecimal string.
    ///
    /// # Returns
    /// A hex-encoded string representation of the proof.
    ///
    /// # Example
    /// ```javascript
    /// const hexString = proof.toHex();
    /// console.log('Proof:', hexString);
    /// ```
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes a proof from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex-encoded string containing the proof data.
    ///
    /// # Returns
    /// The deserialized `AccountAssetRegistrationProof` object.
    ///
    /// # Errors
    /// * Throws an error if the hex string is invalid or contains non-hex characters.
    /// * Throws an error if the decoded bytes don't represent a valid proof.
    ///
    /// # Example
    /// ```javascript
    /// const proof = AccountAssetRegistrationProof.fromHex('0x1234abcd...');
    /// ```
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<AccountAssetRegistrationProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Contains both the registration proof and the resulting account asset state when
/// registering an account for a specific confidential asset.
///
/// This is returned by `AccountKeys.registerAccountAssetProof()` and provides everything
/// needed to register the account on-chain and track the resulting state locally.
///
/// # Example
/// ```javascript
/// const registration = accountKeys.registerAccountAssetProof(assetId, did);
///
/// // Get the proof to submit on-chain
/// const proof = registration.getProof();
/// const results = await signer.registerAccountAsset(proof);
///
/// // Get the state to track locally
/// const accountState = registration.getAccountAssetState();
/// accountState.commitPendingState(results.leafIndex());
/// ```
#[wasm_bindgen]
pub struct AccountAssetRegistration {
    pub(crate) proof: NativeAccountAssetRegistrationProof,
    pub(crate) state: AccountAssetState,
}

#[wasm_bindgen]
impl AccountAssetRegistration {
    /// Gets the registration proof that can be submitted to the blockchain.
    ///
    /// # Returns
    /// An `AccountAssetRegistrationProof` object.
    ///
    /// # Example
    /// ```javascript
    /// const proof = registration.getProof();
    /// const results = await signer.registerAccountAsset(proof);
    /// ```
    #[wasm_bindgen(js_name = getProof)]
    pub fn get_proof(&self) -> AccountAssetRegistrationProof {
        AccountAssetRegistrationProof {
            inner: self.proof.clone(),
        }
    }

    /// Gets the registration proof as a batched proof (containing a single proof).
    ///
    /// This is useful if you want to combine multiple registration proofs into a single
    /// batched transaction later.
    ///
    /// # Returns
    /// A `BatchedAccountAssetRegistrationProof` containing this single proof.
    ///
    /// # Example
    /// ```javascript
    /// const batchedProof = registration.getBatchedProof();
    /// ```
    #[wasm_bindgen(js_name = getBatchedProof)]
    pub fn get_batched_proof(&self) -> BatchedAccountAssetRegistrationProof {
        BatchedAccountAssetRegistrationProof {
            proofs: vec![self.proof.clone()],
        }
    }

    /// Gets the registration proof as SCALE-encoded bytes.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded proof.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = registration.getProofBytes();
    /// console.log('Proof bytes length:', bytes.length);
    /// ```
    #[wasm_bindgen(js_name = getProofBytes)]
    pub fn get_proof_bytes(&self) -> Vec<u8> {
        self.proof.encode()
    }

    /// Gets the batched registration proof as SCALE-encoded bytes.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded batched proof.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = registration.getBatchedProofBytes();
    /// ```
    #[wasm_bindgen(js_name = getBatchedProofBytes)]
    pub fn get_batched_proof_bytes(&self) -> Vec<u8> {
        vec![self.proof.clone()].encode()
    }

    /// Gets the resulting account asset state that should be tracked locally.
    ///
    /// After submitting the registration proof on-chain, you should commit the
    /// transaction results to this state using `commitPendingState()`.
    ///
    /// # Returns
    /// An `AccountAssetState` object that can be used to track the account's
    /// confidential balance and generate future proofs.
    ///
    /// # Example
    /// ```javascript
    /// const accountState = registration.getAccountAssetState();
    ///
    /// // After submitting the proof
    /// const results = await signer.registerAccountAsset(registration.getProof());
    /// accountState.commitPendingState(results.leafIndex());
    ///
    /// // Now you can use the state for future operations
    /// console.log('Balance:', accountState.balance());
    /// ```
    #[wasm_bindgen(js_name = getAccountAssetState)]
    pub fn get_account_asset_state(&self) -> AccountAssetState {
        self.state.clone()
    }
}

/// A zero-knowledge proof that allows minting new confidential assets.
///
/// This proof demonstrates that the account holder has the authority to mint assets
/// without revealing the amount being minted or the account details. Only authorized
/// issuers can generate valid minting proofs for their assets.
///
/// # Example
/// ```javascript
/// const mintingProof = accountState.assetMintingProof(keys, path, 1000000n);
/// const results = await issuer.mintAsset(mintingProof);
/// accountState.commitPendingState(results.leafIndex());
/// ```
#[wasm_bindgen]
pub struct AssetMintingProof {
    pub(crate) inner: NativeAssetMintingProof,
}

#[wasm_bindgen]
impl AssetMintingProof {
    /// Serializes the proof to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded proof.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = mintingProof.toBytes();
    /// console.log('Proof size:', bytes.length, 'bytes');
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes a minting proof from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded minting proof data.
    ///
    /// # Returns
    /// The deserialized `AssetMintingProof` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const mintingProof = AssetMintingProof.fromBytes(storedBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AssetMintingProof, JsValue> {
        let inner = NativeAssetMintingProof::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode minting proof: {}", e)))?;
        Ok(AssetMintingProof { inner })
    }

    /// Exports the proof as a hexadecimal string.
    ///
    /// # Returns
    /// A hex-encoded string representation of the proof.
    ///
    /// # Example
    /// ```javascript
    /// const hexString = mintingProof.toHex();
    /// ```
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes a minting proof from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex-encoded string containing the proof data.
    ///
    /// # Returns
    /// The deserialized `AssetMintingProof` object.
    ///
    /// # Errors
    /// * Throws an error if the hex string is invalid or contains non-hex characters.
    /// * Throws an error if the decoded bytes don't represent a valid proof.
    ///
    /// # Example
    /// ```javascript
    /// const mintingProof = AssetMintingProof.fromHex('0xabcd1234...');
    /// ```
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<AssetMintingProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}
