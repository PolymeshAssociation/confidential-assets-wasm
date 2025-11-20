use codec::{Decode, Encode};
use polymesh_dart::{
    AssetId, Balance, Leg as NativeLeg, LegBuilder as NativeLegBuilder,
    LegEncrypted as NativeLegEncrypted, LegRole as NativeLegRole,
    SettlementBuilder as NativeSettlementBuilder, SettlementProof as NativeSettlementProof,
};
use wasm_bindgen::prelude::*;

use crate::{
    bytes_to_jsvalue, jsvalue_to_balance, jsvalue_to_bytes, AccountKeys, AccountPublicKey,
    AccountPublicKeys, AssetLeafPath, AssetState, AssetTreeRoot, EncryptionKeyPair,
};

mod leg;
pub use leg::*;

/// Builds a confidential settlement transaction with multiple legs.
///
/// A settlement transfers confidential assets between accounts while maintaining privacy
/// through zero-knowledge proofs. This builder collects all the legs (individual transfers)
/// and asset paths needed to create the settlement proof.
///
/// # Example
/// ```javascript
/// // Create a settlement builder
/// const builder = new SettlementBuilder("Transfer memo", blockNumber, assetTreeRoot);
///
/// // Add asset paths (only once per asset)
/// builder.addAssetPath(assetId, assetPath);
///
/// // Add transfer legs
/// const leg = new LegBuilder(senderKeys, receiverKeys, assetState, 1000n);
/// builder.addLeg(leg);
///
/// // Build the proof
/// const proof = builder.build();
/// const result = await signer.createSettlement(proof);
/// ```
#[wasm_bindgen]
pub struct SettlementBuilder {
    pub(crate) inner: NativeSettlementBuilder,
}

#[wasm_bindgen]
impl SettlementBuilder {
    /// Creates a new settlement builder.
    ///
    /// # Arguments
    /// * `memo` - A string or byte array memo/description for this settlement. Accepts:
    ///   - String (will be converted to UTF-8 bytes)
    ///   - Hex string with "0x" prefix
    ///   - `Uint8Array`
    /// * `block_number` - The block number at which the asset tree root was captured (as a number).
    /// * `root` - The asset tree root at the specified block number.
    ///
    /// # Returns
    /// A new `SettlementBuilder` instance.
    ///
    /// # Errors
    /// * Throws an error if the memo cannot be converted to bytes.
    ///
    /// # Example
    /// ```javascript
    /// const blockNumber = await assetCurveTree.getLastBlockNumber();
    /// const root = await assetCurveTree.getRoot(blockNumber);
    /// const builder = new SettlementBuilder("My settlement", blockNumber, root);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(
        memo: JsValue,
        block_number: u32,
        root: &AssetTreeRoot,
    ) -> Result<SettlementBuilder, JsValue> {
        let memo = jsvalue_to_bytes(&memo)?;
        Ok(SettlementBuilder {
            inner: NativeSettlementBuilder::new_root(&memo, block_number, root.root.clone()),
        })
    }

    /// Adds a transfer leg to the settlement.
    ///
    /// Multiple legs can be added to create a multi-leg settlement where multiple
    /// transfers happen atomically.
    ///
    /// # Arguments
    /// * `leg` - A `LegBuilder` containing the transfer details.
    ///
    /// # Example
    /// ```javascript
    /// const leg = new LegBuilder(senderKeys, receiverKeys, assetState, 1000n);
    /// builder.addLeg(leg);
    /// ```
    #[wasm_bindgen(js_name = addLeg)]
    pub fn add_leg(&mut self, leg: &LegBuilder) {
        self.inner.add_leg(leg.to_native());
    }

    /// Adds the curve tree path for an asset in the asset curve tree.
    ///
    /// This path is required for each unique asset used in the settlement legs.
    /// If multiple legs use the same asset, only add the path once.
    ///
    /// # Arguments
    /// * `asset_id` - The numeric identifier of the asset.
    /// * `path` - The asset's curve tree path in the asset curve tree.
    ///
    /// # Errors
    /// * Throws an error if the path cannot be decoded.
    /// * Throws an error if the path has already been added for this asset.
    ///
    /// # Example
    /// ```javascript
    /// const assetPath = await assetCurveTree.getLeafPath(assetState.leafIndex());
    /// builder.addAssetPath(assetId, assetPath);
    /// ```
    #[wasm_bindgen(js_name = addAssetPath)]
    pub fn add_asset_path(
        &mut self,
        asset_id: AssetId,
        path: &AssetLeafPath,
    ) -> Result<(), JsValue> {
        let path = path
            .path
            .decode()
            .map_err(|e| JsValue::from_str(&format!("Failed to decode asset leaf path: {}", e)))?;
        self.inner
            .add_path(asset_id, path)
            .map_err(|e| JsValue::from_str(&format!("Failed to add asset leaf path: {}", e)))?;

        Ok(())
    }

    /// Builds the final settlement proof from all added legs and paths.
    ///
    /// This consumes the builder and generates the zero-knowledge proof that can
    /// be submitted to the blockchain to create the settlement.
    ///
    /// # Returns
    /// A `SettlementProof` ready to be submitted on-chain.
    ///
    /// # Errors
    /// * Throws an error if proof generation fails (e.g., missing asset paths).
    ///
    /// # Example
    /// ```javascript
    /// const proof = builder.build();
    /// const result = await signer.createSettlement(proof);
    /// ```
    #[wasm_bindgen(js_name = build)]
    pub fn build(self) -> Result<SettlementProof, JsValue> {
        let mut rng = rand::rngs::OsRng;
        let proof = self
            .inner
            .build(&mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to build settlement proof: {}", e)))?;
        Ok(SettlementProof { inner: proof })
    }
}

/// Holds the information needed for a single transfer leg in a settlement.
///
/// A leg represents a confidential transfer of a specific amount of an asset from one
/// account to another. The leg builder contains all the public information needed to
/// encrypt the leg details and generate the settlement proof.
///
/// # Example
/// ```javascript
/// // Create a leg to transfer 1000 units from sender to receiver
/// const leg = new LegBuilder(
///     senderPublicKeys,
///     receiverPublicKeys,
///     assetState,
///     1000n  // amount as BigInt
/// );
///
/// // Add to settlement
/// settlementBuilder.addLeg(leg);
/// ```
#[wasm_bindgen(getter_with_clone, inspectable)]
pub struct LegBuilder {
    pub sender: AccountPublicKeys,
    pub receiver: AccountPublicKeys,
    pub asset: AssetState,
    pub amount: Balance,
}

impl LegBuilder {
    pub fn to_native(&self) -> NativeLegBuilder {
        NativeLegBuilder {
            sender: self.sender.to_native(),
            receiver: self.receiver.to_native(),
            asset: self.asset.inner.clone(),
            amount: self.amount,
        }
    }
}

#[wasm_bindgen]
impl LegBuilder {
    /// Creates a new transfer leg for a settlement.
    ///
    /// # Arguments
    /// * `sender` - The sender's account public keys (`AccountPublicKeys`).
    /// * `receiver` - The receiver's account public keys (`AccountPublicKeys`).
    /// * `asset` - The asset state containing mediator and auditor encryption keys (`AssetState`).
    /// * `amount` - The amount to transfer. Accepts:
    ///   - JavaScript number (e.g., `1000`)
    ///   - JavaScript BigInt (e.g., `1000n`)
    ///   - Decimal string (e.g., `"1000"`)
    ///   - Hex string with 0x prefix (e.g., `"0x3e8"`)
    ///
    /// # Returns
    /// A new `LegBuilder` instance.
    ///
    /// # Errors
    /// * Throws an error if the amount format is invalid.
    ///
    /// # On-chain Data
    /// All the required information can be queried from on-chain:
    /// - `confidentialAssets.accountEncryptionKey(accountPublicKey)` - Get encryption keys
    /// - `confidentialAssets.dartAssetDetails(assetId)` - Get asset mediators/auditors
    ///
    /// # Example
    /// ```javascript
    /// const leg = new LegBuilder(
    ///     issuerPublicKeys,
    ///     investorPublicKeys,
    ///     assetState,
    ///     250n  // Transfer 250 units
    /// );
    /// settlementBuilder.addLeg(leg);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(
        sender: &AccountPublicKeys,
        receiver: &AccountPublicKeys,
        asset: &AssetState,
        amount: JsValue,
    ) -> Result<LegBuilder, JsValue> {
        let amount = jsvalue_to_balance(&amount)?;
        Ok(LegBuilder {
            sender: sender.clone(),
            receiver: receiver.clone(),
            asset: asset.clone(),
            amount,
        })
    }
}

/// A collection of encrypted settlement legs.
///
/// This type represents multiple encrypted transfer legs, typically retrieved from
/// a settlement on-chain or extracted from a settlement proof. Each leg can be
/// independently decrypted if you have the appropriate keys.
///
/// # Example
/// ```javascript
/// const encryptedLegs = await client.getSettlementLegs(settlementRef);
/// console.log('Settlement has', encryptedLegs.legCount(), 'legs');
///
/// // Try to decrypt all legs
/// const decryptedLegs = encryptedLegs.tryDecrypt(accountKeys);
/// for (let i = 0; i < decryptedLegs.legCount(); i++) {
///     const leg = decryptedLegs.getLeg(i);
///     if (leg) {
///         console.log(`Leg ${i}: ${leg.amount} units`);
///     }
/// }
/// ```
#[wasm_bindgen]
pub struct SettlementLegsEncrypted {
    pub(crate) inner: Vec<NativeLegEncrypted>,
}

#[wasm_bindgen]
impl SettlementLegsEncrypted {
    /// Gets the number of encrypted legs.
    ///
    /// # Returns
    /// The count of legs as a number.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Number of legs:', encryptedLegs.legCount());
    /// ```
    #[wasm_bindgen(js_name = legCount)]
    pub fn leg_count(&self) -> usize {
        self.inner.len()
    }

    /// Gets an encrypted leg by its index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the leg to retrieve.
    ///
    /// # Returns
    /// * `Some(SettlementLegEncrypted)` if the index is valid.
    /// * `None` if the index is out of bounds.
    ///
    /// # Example
    /// ```javascript
    /// const leg = encryptedLegs.getLeg(0);
    /// if (leg) {
    ///     const decrypted = leg.tryDecrypt(accountKeys);
    /// }
    /// ```
    #[wasm_bindgen(js_name = getLeg)]
    pub fn get_leg(&self, index: usize) -> Option<SettlementLegEncrypted> {
        self.inner
            .get(index)
            .map(|leg| SettlementLegEncrypted { inner: leg.clone() })
    }

    /// Serializes all encrypted legs to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded encrypted legs.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = encryptedLegs.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes encrypted legs from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded encrypted legs data.
    ///
    /// # Returns
    /// The deserialized `SettlementLegsEncrypted`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const encryptedLegs = SettlementLegsEncrypted.fromBytes(legsBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SettlementLegsEncrypted, JsValue> {
        let inner = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode encrypted legs: {}", e)))?;
        Ok(SettlementLegsEncrypted { inner })
    }

    /// Attempts to decrypt all legs using account keys.
    ///
    /// This method tries to decrypt each leg. Successfully decrypted legs (where you are
    /// the sender or receiver) will be `Some`, while legs you're not involved in will be `None`.
    ///
    /// # Arguments
    /// * `account_keys` - The account keys to use for decryption.
    ///
    /// # Returns
    /// A `SettlementLegs` object where each leg is either decrypted (`Some`) or not (`None`).
    ///
    /// # Example
    /// ```javascript
    /// const decryptedLegs = encryptedLegs.tryDecrypt(accountKeys);
    /// for (let i = 0; i < decryptedLegs.legCount(); i++) {
    ///     const leg = decryptedLegs.getLeg(i);
    ///     if (leg) {
    ///         console.log(`Leg ${i}: Received ${leg.amount} units`);
    ///     }
    /// }
    /// ```
    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(&self, account_keys: &AccountKeys) -> SettlementLegs {
        let mut legs = Vec::with_capacity(self.inner.len());
        for leg_enc in &self.inner {
            let leg = leg_enc
                .try_decrypt(&account_keys.inner)
                .map(|(leg, role)| SettlementLeg::from_native(leg, role));
            legs.push(leg);
        }
        SettlementLegs { legs }
    }

    /// Attempts to decrypt all legs as a mediator or auditor.
    ///
    /// Mediators and auditors can decrypt all legs in a settlement to verify transactions
    /// even if they are not the sender or receiver.
    ///
    /// # Arguments
    /// * `encryption_key` - The encryption key pair for the mediator or auditor.
    ///
    /// # Returns
    /// A `SettlementLegs` object where each leg is either decrypted (`Some`) or not (`None`).
    ///
    /// # Example
    /// ```javascript
    /// const mediatorKeys = accountKeys.encryptionKeyPair();
    /// const decryptedLegs = encryptedLegs.tryDecryptAsMediatorOrAuditor(mediatorKeys);
    /// console.log('As mediator, can see', decryptedLegs.legCount(), 'legs');
    /// ```
    #[wasm_bindgen(js_name = tryDecryptAsMediatorOrAuditor)]
    pub fn try_decrypt_as_mediator_or_auditor(
        &self,
        encryption_key: &EncryptionKeyPair,
    ) -> SettlementLegs {
        let mut legs = Vec::with_capacity(self.inner.len());
        for leg_enc in &self.inner {
            let leg = leg_enc
                .try_decrypt_with_key(&encryption_key.inner, None, None)
                .ok()
                .map(|(leg, role)| SettlementLeg::from_native(leg, role));
            legs.push(leg);
        }

        SettlementLegs { legs }
    }
}

/// A collection of decrypted (or partially decrypted) settlement legs.
///
/// This type represents the result of attempting to decrypt multiple legs. Each leg
/// may be `Some` (successfully decrypted) or `None` (not decrypted, either because
/// you don't have the right keys or you're not involved in that leg).
///
/// # Example
/// ```javascript
/// const decryptedLegs = encryptedLegs.tryDecrypt(accountKeys);
/// for (let i = 0; i < decryptedLegs.legCount(); i++) {
///     const leg = decryptedLegs.getLeg(i);
///     if (leg) {
///         console.log(`Leg ${i}:`);
///         console.log('  Sender:', leg.sender.toJson());
///         console.log('  Receiver:', leg.receiver.toJson());
///         console.log('  Amount:', leg.amount);
///     } else {
///         console.log(`Leg ${i}: Could not decrypt (not involved)`);
///     }
/// }
/// ```
#[wasm_bindgen]
pub struct SettlementLegs {
    pub(crate) legs: Vec<Option<SettlementLeg>>,
}

#[wasm_bindgen]
impl SettlementLegs {
    /// Gets the total number of legs (both decrypted and not decrypted).
    ///
    /// # Returns
    /// The count of legs as a number.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Total legs:', decryptedLegs.legCount());
    /// ```
    #[wasm_bindgen(js_name = legCount)]
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    /// Gets a decrypted leg by its index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the leg to retrieve.
    ///
    /// # Returns
    /// * `Some(SettlementLeg)` if the index is valid and the leg was successfully decrypted.
    /// * `None` if the index is out of bounds or the leg could not be decrypted.
    ///
    /// # Example
    /// ```javascript
    /// const leg = decryptedLegs.getLeg(0);
    /// if (leg) {
    ///     console.log('Decrypted leg amount:', leg.amount);
    /// } else {
    ///     console.log('Leg not decrypted or index invalid');
    /// }
    /// ```
    #[wasm_bindgen(js_name = getLeg)]
    pub fn get_leg(&self, index: usize) -> Option<SettlementLeg> {
        if index >= self.legs.len() {
            None
        } else {
            self.legs[index].clone()
        }
    }
}

/// Represents an encrypted settlement leg retrieved from the blockchain.
///
/// Settlement legs are encrypted so that only the sender, receiver, mediators,
/// and auditors can decrypt the transfer details. This type provides methods
/// to decrypt the leg if you have the appropriate keys.
///
/// # Example
/// ```javascript
/// // Retrieve encrypted legs from chain
/// const encryptedLegs = await client.getSettlementLegs(settlementRef);
/// const encryptedLeg = encryptedLegs.getLeg(0);
///
/// // Try to decrypt as account holder
/// const decrypted = encryptedLeg.tryDecrypt(accountKeys);
/// if (decrypted) {
///     console.log('Sender:', decrypted.sender);
///     console.log('Amount:', decrypted.amount);
/// }
/// ```
#[wasm_bindgen]
pub struct SettlementLegEncrypted {
    pub(crate) inner: NativeLegEncrypted,
}

#[wasm_bindgen]
impl SettlementLegEncrypted {
    /// Serializes the encrypted leg to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded encrypted leg.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = encryptedLeg.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes an encrypted leg from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded encrypted leg data.
    ///
    /// # Returns
    /// The deserialized `SettlementLegEncrypted`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const encryptedLeg = SettlementLegEncrypted.fromBytes(legBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SettlementLegEncrypted, JsValue> {
        let inner = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode encrypted leg: {}", e)))?;
        Ok(SettlementLegEncrypted { inner })
    }

    /// Exports the encrypted leg as a hexadecimal string.
    ///
    /// # Returns
    /// A hex-encoded string representation of the encrypted leg.
    ///
    /// # Example
    /// ```javascript
    /// const hexString = encryptedLeg.toHex();
    /// ```
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes an encrypted leg from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex-encoded string (with or without "0x" prefix).
    ///
    /// # Returns
    /// The deserialized `SettlementLegEncrypted`.
    ///
    /// # Errors
    /// * Throws an error if the hex string is invalid.
    ///
    /// # Example
    /// ```javascript
    /// const encryptedLeg = SettlementLegEncrypted.fromHex("0x1234...");
    /// ```
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<SettlementLegEncrypted, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Attempts to decrypt the leg using account keys.
    ///
    /// This method tries to decrypt the leg if you are the sender or receiver of the transfer.
    ///
    /// # Arguments
    /// * `account_keys` - The account keys to use for decryption.
    ///
    /// # Returns
    /// * `Some(SettlementLeg)` if decryption succeeded (you are the sender or receiver).
    /// * `None` if decryption failed (you are not involved in this leg).
    ///
    /// # Example
    /// ```javascript
    /// const decrypted = encryptedLeg.tryDecrypt(accountKeys);
    /// if (decrypted) {
    ///     console.log('Sender:', decrypted.sender);
    ///     console.log('Receiver:', decrypted.receiver);
    ///     console.log('Amount:', decrypted.amount);
    /// } else {
    ///     console.log('Not involved in this leg');
    /// }
    /// ```
    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(
        &self,
        account_keys: &AccountKeys,
    ) -> Result<Option<SettlementLeg>, JsValue> {
        if let Some((leg, role)) = self.inner.try_decrypt(&account_keys.inner) {
            Ok(Some(SettlementLeg::from_native(leg, role)))
        } else {
            Ok(None)
        }
    }

    /// Attempts to decrypt the leg as a mediator or auditor.
    ///
    /// Mediators and auditors can decrypt all legs in a settlement to verify and approve transactions.
    ///
    /// # Arguments
    /// * `encryption_key` - The encryption key pair for the mediator or auditor.
    /// * `max_asset_id` - Optional maximum asset ID to limit decryption scope.
    ///
    /// # Returns
    /// * `Some(SettlementLeg)` if decryption succeeded.
    /// * `None` if decryption failed (you are not a mediator/auditor for this asset).
    ///
    /// # Example
    /// ```javascript
    /// const mediatorKeys = accountKeys.encryptionKeyPair();
    /// const maxAssetId = 500; // Optional limit
    /// const decrypted = encryptedLeg.tryDecryptAsMediatorOrAuditor(mediatorKeys, maxAssetId);
    /// if (decrypted) {
    ///     console.log('Can see transfer details as mediator/auditor');
    ///     console.log('Amount:', decrypted.amount);
    /// }
    /// ```
    #[wasm_bindgen(js_name = tryDecryptAsMediatorOrAuditor)]
    pub fn try_decrypt_as_mediator_or_auditor(
        &self,
        encryption_key: &EncryptionKeyPair,
        max_asset_id: Option<AssetId>,
    ) -> Result<Option<SettlementLeg>, JsValue> {
        if let Some((leg, role)) = self
            .inner
            .try_decrypt_with_key(&encryption_key.inner, None, max_asset_id)
            .ok()
        {
            Ok(Some(SettlementLeg::from_native(leg, role)))
        } else {
            Ok(None)
        }
    }
}

/// Represents a decrypted settlement leg with visible transfer details.
///
/// This type contains the plaintext information about a transfer after successful decryption.
/// The fields are accessible as properties in JavaScript.
///
/// # Properties
/// * `sender` - The sender's account public key (`AccountPublicKey`)
/// * `receiver` - The receiver's account public key (`AccountPublicKey`)
/// * `assetId` - The asset identifier (number)
/// * `amount` - The transfer amount (number)
///
/// # Example
/// ```javascript
/// const leg = encryptedLeg.tryDecrypt(accountKeys);
/// if (leg) {
///     console.log('Sender:', leg.sender.toJson());
///     console.log('Receiver:', leg.receiver.toJson());
///     console.log('Asset ID:', leg.assetId);
///     console.log('Amount:', leg.amount);
/// }
/// ```
#[wasm_bindgen(getter_with_clone, inspectable)]
#[derive(Clone, Debug)]
pub struct SettlementLeg {
    pub role: Option<String>,
    pub sender: AccountPublicKey,
    pub receiver: AccountPublicKey,
    #[wasm_bindgen(js_name = "assetId")]
    pub asset_id: AssetId,
    pub amount: Balance,
}

impl SettlementLeg {
    pub fn from_native(leg: NativeLeg, role: NativeLegRole) -> SettlementLeg {
        SettlementLeg {
            role: Some(match role {
                NativeLegRole::Sender => "Sender".to_string(),
                NativeLegRole::Receiver => "Receiver".to_string(),
                NativeLegRole::Mediator(_) => "Mediator".to_string(),
                NativeLegRole::Auditor(_) => "Auditor".to_string(),
            }),
            sender: AccountPublicKey::from_native(leg.sender),
            receiver: AccountPublicKey::from_native(leg.receiver),
            asset_id: leg.asset_id,
            amount: leg.amount,
        }
    }
}

/// A zero-knowledge proof for creating a confidential settlement on-chain.
///
/// This proof demonstrates that a settlement is valid (senders have sufficient balances,
/// all transfers are properly encrypted) without revealing any confidential information.
/// The proof is generated by `SettlementBuilder.build()` and submitted via
/// `PolymeshSigner.createSettlement()`.
///
/// # Example
/// ```javascript
/// const proof = settlementBuilder.build();
/// const result = await signer.createSettlement(proof);
/// console.log('Settlement created:', result.settlementId());
/// ```
#[wasm_bindgen]
pub struct SettlementProof {
    pub(crate) inner: NativeSettlementProof,
}

#[wasm_bindgen]
impl SettlementProof {
    /// Serializes the settlement proof to a SCALE-encoded byte array.
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

    /// Deserializes a settlement proof from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded proof data.
    ///
    /// # Returns
    /// The deserialized `SettlementProof`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const proof = SettlementProof.fromBytes(proofBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SettlementProof, JsValue> {
        let inner = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode settlement proof: {}", e)))?;
        Ok(SettlementProof { inner })
    }

    /// Gets the settlement memo/description.
    ///
    /// # Returns
    /// The memo as a string (if valid UTF-8) or hex string (if binary data).
    ///
    /// # Example
    /// ```javascript
    /// const memo = proof.getMemo();
    /// console.log('Settlement memo:', memo);
    /// ```
    #[wasm_bindgen(js_name = getMemo)]
    pub fn get_memo(&self) -> JsValue {
        bytes_to_jsvalue(&self.inner.memo)
    }

    /// Gets the block number at which the asset tree root was captured.
    ///
    /// This is the block number used for the asset leaf paths in the proof.
    ///
    /// # Returns
    /// The block number as a number.
    ///
    /// # Example
    /// ```javascript
    /// const blockNumber = proof.getBlockNumber();
    /// console.log('Proof uses asset tree at block:', blockNumber);
    /// ```
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> u32 {
        self.inner.root_block
    }

    /// Gets the number of legs in this settlement.
    ///
    /// # Returns
    /// The count of transfer legs as a number.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Settlement has', proof.getLegCount(), 'legs');
    /// ```
    #[wasm_bindgen(js_name = getLegCount)]
    pub fn get_leg_count(&self) -> usize {
        self.inner.legs.len()
    }

    /// Extracts the encrypted legs from the settlement proof.
    ///
    /// The encrypted legs contain the transfer details that can only be decrypted
    /// by the involved parties (sender, receiver, mediators, auditors).
    ///
    /// # Returns
    /// A `SettlementLegsEncrypted` object containing all encrypted legs.
    ///
    /// # Example
    /// ```javascript
    /// const encryptedLegs = proof.getEncryptedLegs();
    /// const decryptedLegs = encryptedLegs.tryDecrypt(accountKeys);
    /// ```
    #[wasm_bindgen(js_name = getEncryptedLegs)]
    pub fn get_encrypted_legs(&self) -> SettlementLegsEncrypted {
        let legs = self
            .inner
            .legs
            .iter()
            .map(|proof| proof.leg_enc.clone())
            .collect();

        SettlementLegsEncrypted { inner: legs }
    }
}
