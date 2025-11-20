use codec::{Decode, Encode};
use polymesh_dart::{
    curve_tree::get_account_curve_tree_parameters,
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountKeys as NativeAccountKeys, AccountPublicKey as NativeAccountPublicKey,
    AccountPublicKeys as NativeAccountPublicKeys,
    AccountRegistrationProof as NativeAccountRegistrationProof, AssetId,
    EncryptionKeyPair as NativeEncryptionKeyPair, EncryptionPublicKey as NativeEncryptionPublicKey,
    LegId, LegRef, LegRole, MediatorAffirmationProof as NativeMediatorAffirmationProof,
};
use rand::RngCore as _;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{
    jsvalue_to_balance, jsvalue_to_identity_id, jsvalue_to_settlement_ref,
    AccountAssetRegistration, AccountAssetState, MediatorAffirmationProof, SettlementLegEncrypted,
};

/// Contains the secret keys for a confidential account.
///
/// This type holds both the account secret key (used for generating zero-knowledge proofs)
/// and the encryption secret key (used for decrypting settlement leg information). These keys
/// are essential for all confidential asset operations including registration, minting,
/// and settlements.
///
/// **Security Warning:** These keys should be kept secure and never shared. Loss of these
/// keys means permanent loss of access to the confidential account.
///
/// # Example
/// ```javascript
/// // Generate from a deterministic seed
/// const keys = AccountKeys.fromSeed("my-secure-seed-phrase");
///
/// // Generate from a random hex seed
/// const randomSeed = generateRandomSeed();
/// const keys = new AccountKeys(randomSeed);
///
/// // Get public keys for sharing
/// const publicKeys = keys.publicKeys();
/// ```
#[wasm_bindgen]
pub struct AccountKeys {
    pub(crate) inner: NativeAccountKeys,
}

#[wasm_bindgen]
impl AccountKeys {
    /// Creates new account keys from a hexadecimal seed string.
    ///
    /// # Arguments
    /// * `seed_hex` - A 32-byte hexadecimal string (64 hex characters), with or without "0x" prefix.
    ///
    /// # Returns
    /// A new `AccountKeys` object containing the generated secret keys.
    ///
    /// # Errors
    /// * Throws an error if the seed is not valid hexadecimal.
    /// * Throws an error if the seed is not exactly 32 bytes (64 hex characters).
    ///
    /// # Example
    /// ```javascript
    /// const seed = generateRandomSeed(); // Returns a 64-character hex string
    /// const keys = new AccountKeys(seed);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(seed_hex: &str) -> Result<AccountKeys, JsValue> {
        let seed_bytes = hex::decode(seed_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex seed: {}", e)))?;

        if seed_bytes.len() != 32 {
            return Err(JsValue::from_str(
                "Seed must be 32 bytes (64 hex characters)",
            ));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let mut rng = ChaChaRng::from_seed(seed);
        let inner = NativeAccountKeys::rand(&mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate keys: {}", e)))?;

        Ok(AccountKeys { inner })
    }

    /// Creates account keys from any seed string using deterministic hashing.
    ///
    /// This is a convenience method that accepts any string and hashes it to create
    /// a deterministic 32-byte seed. The same input string will always produce the
    /// same keys.
    ///
    /// # Arguments
    /// * `seed` - Any string to use as the seed (will be hashed internally).
    ///
    /// # Returns
    /// A new `AccountKeys` object.
    ///
    /// # Errors
    /// * Throws an error if key generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const keys = AccountKeys.fromSeed("my-secure-passphrase");
    /// // Same seed always produces the same keys
    /// const keys2 = AccountKeys.fromSeed("my-secure-passphrase");
    /// ```
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &str) -> Result<AccountKeys, JsValue> {
        let inner = NativeAccountKeys::from_seed(seed)
            .map_err(|e| JsValue::from_str(&format!("Failed to create keys from seed: {}", e)))?;
        Ok(AccountKeys { inner })
    }

    /// Serializes the account keys to a SCALE-encoded byte array.
    ///
    /// **Security Warning:** This exports the secret keys. The resulting bytes should
    /// be encrypted before storage and never transmitted over insecure channels.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded secret keys.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = keys.toBytes();
    /// // Encrypt bytes before storing!
    /// const encrypted = encryptData(bytes);
    /// localStorage.setItem('encryptedKeys', encrypted);
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes account keys from a SCALE-encoded byte array.
    ///
    /// **Security Warning:** Only use this with bytes from a trusted, secure source.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded account keys.
    ///
    /// # Returns
    /// The deserialized `AccountKeys` object.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const decrypted = decryptData(encryptedKeys);
    /// const keys = AccountKeys.fromBytes(decrypted);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountKeys, JsValue> {
        let inner = NativeAccountKeys::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode account keys: {}", e)))?;
        Ok(AccountKeys { inner })
    }

    /// Extracts the public keys from these account keys.
    ///
    /// Public keys can be safely shared and are used for account registration,
    /// receiving settlements, and encryption.
    ///
    /// # Returns
    /// An `AccountPublicKeys` object containing both the account public key and encryption public key.
    ///
    /// # Example
    /// ```javascript
    /// const publicKeys = keys.publicKeys();
    /// console.log('Account key:', publicKeys.accountPublicKey().toJson());
    /// console.log('Encryption key:', publicKeys.encryptionPublicKey().toJson());
    /// ```
    #[wasm_bindgen(js_name = publicKeys)]
    pub fn public_keys(&self) -> AccountPublicKeys {
        let keys = self.inner.public_keys();
        AccountPublicKeys::from_native(keys)
    }

    /// Extracts the encryption key pair from these account keys.
    ///
    /// The encryption key pair is used to decrypt settlement leg information and
    /// encrypted transaction data.
    ///
    /// # Returns
    /// An `EncryptionKeyPair` object containing the encryption secret key.
    ///
    /// # Example
    /// ```javascript
    /// const encryptionKeys = keys.encryptionKeyPair();
    /// // Use for decrypting settlement legs
    /// const decrypted = settlementLegs.tryDecryptAsMediatorOrAuditor(encryptionKeys);
    /// ```
    #[wasm_bindgen(js_name = encryptionKeyPair)]
    pub fn encryption_key_pair(&self) -> EncryptionKeyPair {
        EncryptionKeyPair {
            inner: self.inner.enc.clone(),
        }
    }

    /// Generates a zero-knowledge proof for registering this account on-chain.
    ///
    /// This proof demonstrates that the account holder possesses the secret keys
    /// corresponding to the public keys being registered, without revealing the secret keys.
    ///
    /// # Arguments
    /// * `did` - The identity ID (DID) to link this account to. Accepts:
    ///   - Hex string with or without "0x" prefix (e.g., "0x1234...")
    ///   - 32-byte `Uint8Array`
    ///
    /// # Returns
    /// An `AccountRegistrationProof` that can be submitted to the blockchain.
    ///
    /// # Errors
    /// * Throws an error if the DID format is invalid.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const proof = keys.registerAccountProof(myDid);
    /// const result = await signer.registerAccount(proof);
    /// ```
    #[wasm_bindgen(js_name = registerAccountProof)]
    pub fn register_account_proof(
        &self,
        did: JsValue,
    ) -> Result<AccountRegistrationProof, JsValue> {
        let mut rng = rand::rngs::OsRng;
        let did = jsvalue_to_identity_id(&did)?;
        let proof =
            NativeAccountRegistrationProof::<()>::new(&mut rng, &[self.inner.clone()], &did.0[..])
                .map_err(|e| {
                    JsValue::from_str(&format!("Failed to generate registration proof: {}", e))
                })?;

        Ok(AccountRegistrationProof { inner: proof })
    }

    /// Generates a zero-knowledge proof for registering this account for a specific asset.
    ///
    /// This proof allows the account to participate in confidential transactions for the
    /// specified asset. After registration, the account can mint, transfer, and receive
    /// the asset while maintaining confidentiality.
    ///
    /// # Arguments
    /// * `asset_id` - The numeric identifier of the confidential asset.
    /// * `did` - The identity ID (DID) of the account holder. Accepts:
    ///   - Hex string with or without "0x" prefix (e.g., "0x1234...")
    ///   - 32-byte `Uint8Array`
    ///
    /// # Returns
    /// An `AccountAssetRegistration` containing both the proof and the initial account state.
    ///
    /// # Errors
    /// * Throws an error if the DID format is invalid.
    /// * Throws an error if proof generation fails.
    ///
    /// # Example
    /// ```javascript
    /// const registration = keys.registerAccountAssetProof(assetId, myDid);
    /// const proof = registration.getProof();
    /// const result = await signer.registerAccountAsset(proof);
    ///
    /// // Track the account state
    /// const accountState = registration.getAccountAssetState();
    /// accountState.commitPendingState(result.leafIndex());
    /// ```
    #[wasm_bindgen(js_name = registerAccountAssetProof)]
    pub fn register_account_asset_proof(
        &self,
        asset_id: u32,
        did: JsValue,
    ) -> Result<AccountAssetRegistration, JsValue> {
        let mut rng = rand::rngs::OsRng;
        let did = jsvalue_to_identity_id(&did)?;

        let account = self.inner.acct.clone();
        let params = get_account_curve_tree_parameters();

        let (proof, state) = NativeAccountAssetRegistrationProof::new(
            &mut rng,
            &account,
            asset_id,
            0,
            &did.0[..],
            &params,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to generate account asset registration proof: {}",
                e
            ))
        })?;

        let state = AccountAssetState::new(state);

        Ok(AccountAssetRegistration { proof, state })
    }
}

/// Contains the encryption secret key for decrypting confidential transaction data.
///
/// This type is used by mediators and auditors to decrypt settlement leg information.
/// It can also be extracted from `AccountKeys` for accounts to decrypt their own
/// transaction details.
///
/// # Example
/// ```javascript
/// // Extract from account keys
/// const encKeyPair = accountKeys.encryptionKeyPair();
///
/// // Decrypt settlement legs as mediator/auditor
/// const decryptedLegs = settlementLegs.tryDecryptAsMediatorOrAuditor(encKeyPair);
/// ```
#[wasm_bindgen]
pub struct EncryptionKeyPair {
    pub(crate) inner: NativeEncryptionKeyPair,
}

#[wasm_bindgen]
impl EncryptionKeyPair {
    /// Generate mediator affirmation for a settlement leg.
    ///
    /// # Arguments
    /// * `settlement_ref` - The settlement reference (can be hex string or Uint8Array).
    /// * `leg_id` - The identifier of the settlement leg.
    /// * `leg_enc` - The encrypted settlement leg.
    /// * `accept` - Boolean indicating whether to accept (true) or reject (false) the leg.
    /// * `asset_id` - The asset ID of the settlement leg.
    /// * `amount` - The expected amount (can be null/undefined to skip check).
    ///
    /// # Returns
    /// A `MediatorAffirmationProof` that can be submitted to the blockchain.
    ///
    /// # Errors
    /// * Throws an error if decryption fails.
    /// * Throws an error if asset ID or amount do not match.
    /// * Throws an error if the account is not a mediator for the leg.
    #[wasm_bindgen(js_name = mediatorAffirmationProof)]
    pub fn mediator_affirmation_proof(
        &self,
        settlement_ref: JsValue,
        leg_id: LegId,
        leg_enc: &SettlementLegEncrypted,
        accept: bool,
        asset_id: AssetId,
        amount: JsValue,
    ) -> Result<MediatorAffirmationProof, JsValue> {
        let settlement_ref = jsvalue_to_settlement_ref(&settlement_ref)?;
        let leg_ref = LegRef::new(settlement_ref, leg_id);
        let mut rng = rand::rngs::OsRng;
        let leg_enc = &leg_enc.inner;

        // Decrypt leg.
        let (leg, leg_role) = leg_enc
            .try_decrypt_with_key(&self.inner, None, None)
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

        // Only mediators can affirm/reject
        let key_index = match leg_role {
            LegRole::Mediator(idx) => idx,
            _ => {
                return Err(JsValue::from_str(
                    "Only mediators can affirm or reject settlement legs",
                ))
            }
        };

        let proof = NativeMediatorAffirmationProof::new(
            &mut rng,
            &leg_ref,
            asset_id,
            &leg_enc,
            &self.inner,
            key_index,
            accept,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to generate mediator affirmation proof: {}",
                e
            ))
        })?;

        Ok(MediatorAffirmationProof { inner: proof })
    }
}

/// A zero-knowledge proof for registering a confidential account on-chain.
///
/// This proof demonstrates ownership of the account keys without revealing the secret keys.
/// It must be submitted via `PolymeshSigner.registerAccount()` to create the account on-chain.
///
/// # Example
/// ```javascript
/// const proof = accountKeys.registerAccountProof(myDid);
/// const result = await signer.registerAccount(proof);
/// console.log('Account registered with leaf index:', result.leafIndex());
/// ```
#[wasm_bindgen]
pub struct AccountRegistrationProof {
    pub(crate) inner: NativeAccountRegistrationProof<()>,
}

#[wasm_bindgen]
impl AccountRegistrationProof {
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
    /// The deserialized `AccountRegistrationProof`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const proof = AccountRegistrationProof.fromBytes(proofBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountRegistrationProof, JsValue> {
        let inner = NativeAccountRegistrationProof::<()>::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode registration proof: {}", e))
        })?;
        Ok(AccountRegistrationProof { inner })
    }
}

/// Contains both the account public key and encryption public key for a confidential account.
///
/// This type combines the two public keys needed for confidential asset operations:
/// - The account public key identifies the account in the account curve tree
/// - The encryption public key allows others to encrypt data for this account
///
/// These keys can be safely shared publicly and are required for others to send
/// confidential assets to this account.
///
/// # Example
/// ```javascript
/// const publicKeys = accountKeys.publicKeys();
///
/// // Access individual keys
/// const accountKey = publicKeys.accountPublicKey();
/// const encryptionKey = publicKeys.encryptionPublicKey();
///
/// // Use in settlement legs
/// const leg = new LegBuilder(senderKeys, publicKeys, assetState, amount);
/// ```
#[wasm_bindgen]
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct AccountPublicKeys {
    #[serde(rename = "encryptionPublicKey")]
    pub(crate) encryption: EncryptionPublicKey,
    #[serde(rename = "accountPublicKey")]
    pub(crate) account: AccountPublicKey,
}

impl AccountPublicKeys {
    /// Convert from native AccountPublicKeys
    pub fn from_native(native: NativeAccountPublicKeys) -> AccountPublicKeys {
        AccountPublicKeys {
            encryption: EncryptionPublicKey { inner: native.enc },
            account: AccountPublicKey { inner: native.acct },
        }
    }

    /// Convert to native AccountPublicKeys
    pub fn to_native(&self) -> NativeAccountPublicKeys {
        NativeAccountPublicKeys {
            enc: self.encryption.inner,
            acct: self.account.inner,
        }
    }
}

#[wasm_bindgen]
impl AccountPublicKeys {
    /// Creates `AccountPublicKeys` from various input formats.
    ///
    /// # Arguments
    /// * `js_value` - Can be any of:
    ///   - A 64-byte `Uint8Array`
    ///   - JS map/object with `accountPublicKey` and `encryptionPublicKey` properties
    ///
    /// # Returns
    /// A new `AccountPublicKeys` object.
    ///
    /// # Errors
    /// * Throws an error if the input format is not recognized or invalid.
    ///
    /// # Example
    /// ```javascript
    /// // From Uint8Array
    /// const publicKeys = new AccountPublicKeys(uint8Array);
    ///
    /// // From JS object
    /// const publicKeys = new AccountPublicKeys({
    ///   accountPublicKey: "0x1234...",
    ///   encryptionPublicKey: "0x5678..."
    /// });
    ///
    /// // Use in settlement legs
    /// const leg = new LegBuilder(senderKeys, publicKeys, assetState, amount);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(keys: JsValue) -> Result<AccountPublicKeys, JsValue> {
        // Try Uint8Array (check if it's a valid Uint8Array)
        let bytes_array = js_sys::Uint8Array::new(&keys);
        if bytes_array.length() > 0 {
            let bytes_vec = bytes_array.to_vec();
            if !bytes_vec.is_empty() {
                let native = NativeAccountPublicKeys::decode(&mut &bytes_vec[..]).map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to decode account public keys from Uint8Array: {}",
                        e
                    ))
                })?;
                return Ok(AccountPublicKeys::from_native(native));
            }
        }

        // Try JS map/object by using `serde_wasm_bindgen`
        serde_wasm_bindgen::from_value(keys).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode account public keys from object: {}",
                e
            ))
        })
    }

    /// Serializes the public keys to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded public keys.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = publicKeys.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_native().encode()
    }

    /// Deserializes public keys from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded public keys.
    ///
    /// # Returns
    /// The deserialized `AccountPublicKeys`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const publicKeys = AccountPublicKeys.fromBytes(publicKeyBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountPublicKeys, JsValue> {
        let inner = NativeAccountPublicKeys::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode public keys: {}", e)))?;
        Ok(AccountPublicKeys::from_native(inner))
    }

    /// Extracts the account public key component.
    ///
    /// # Returns
    /// The `AccountPublicKey` used for account identification in the curve tree.
    ///
    /// # Example
    /// ```javascript
    /// const accountKey = publicKeys.accountPublicKey();
    /// ```
    #[wasm_bindgen(js_name = accountPublicKey)]
    pub fn account_public_key(&self) -> AccountPublicKey {
        self.account
    }

    /// Extracts the encryption public key component.
    ///
    /// # Returns
    /// The `EncryptionPublicKey` used for encrypting data to this account.
    ///
    /// # Example
    /// ```javascript
    /// const encryptionKey = publicKeys.encryptionPublicKey();
    /// ```
    #[wasm_bindgen(js_name = encryptionPublicKey)]
    pub fn encryption_public_key(&self) -> EncryptionPublicKey {
        self.encryption
    }

    /// Exports the public keys as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the public keys.
    ///
    /// # Errors
    /// * Throws an error if serialization to JSON fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Public Keys:', publicKeys.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }

    /// Exports the public keys as a JsValue for interoperability.
    #[wasm_bindgen(js_name = toJs)]
    pub fn to_js(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(self).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to serialize AccountPublicKeys to JsValue: {}",
                e
            ))
        })
    }

    /// Import public keys from a JsValue.
    #[wasm_bindgen(js_name = fromJs)]
    pub fn from_js(js_value: JsValue) -> Result<AccountPublicKeys, JsValue> {
        serde_wasm_bindgen::from_value(js_value).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize AccountPublicKeys from JsValue: {}",
                e
            ))
        })
    }
}

/// The public key component used for account identification in the account curve tree.
///
/// This key is derived from the account secret key and is used to create account
/// commitments and verify zero-knowledge proofs. It can be safely shared publicly.
///
/// # Example
/// ```javascript
/// // From AccountPublicKeys
/// const accountKey = publicKeys.accountPublicKey();
///
/// // From hex string or bytes
/// const accountKey = new AccountPublicKey("0x1234...");
/// const accountKey = new AccountPublicKey(uint8Array);
/// ```
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountPublicKey {
    pub(crate) inner: NativeAccountPublicKey,
}

impl AccountPublicKey {
    /// Convert from native AccountPublicKey
    pub fn from_native(native: NativeAccountPublicKey) -> AccountPublicKey {
        AccountPublicKey { inner: native }
    }
}

#[wasm_bindgen]
impl AccountPublicKey {
    /// Creates a new account public key from various input formats.
    ///
    /// # Arguments
    /// * `js_value` - Can be any of:
    ///   - A hex string with or without "0x" prefix (e.g., "0x1234...")
    ///   - A 32-byte `Uint8Array`
    ///   - A Polkadot.js `Codec` object with a `.toU8a()` method
    ///
    /// # Returns
    /// A new `AccountPublicKey` object.
    ///
    /// # Errors
    /// * Throws an error if the input format is not recognized or invalid.
    /// * Throws an error if the decoded key is not 32 bytes.
    ///
    /// # Example
    /// ```javascript
    /// // From hex string
    /// const key1 = new AccountPublicKey("0x1234...");
    ///
    /// // From Uint8Array
    /// const key2 = new AccountPublicKey(new Uint8Array(32));
    ///
    /// // From Polkadot.js Codec
    /// const assetDetail = await api.query.confidentialAssets.dartAssetDetails(assetId);
    /// const auditor = assetDetail.auditors[0]; // Auditor key from chain storage
    /// const key4 = new AccountPublicKey(auditor); // Automatically calls toU8a()
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(js_value: JsValue) -> Result<AccountPublicKey, JsValue> {
        // Try string (hex format)
        if let Some(js_str) = js_value.as_string() {
            return NativeAccountPublicKey::from_str(&js_str)
                .map(|key| AccountPublicKey { inner: key })
                .map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to decode account public key from hex string: {}",
                        e
                    ))
                });
        }

        // Try Uint8Array (check if it's a valid Uint8Array)
        let bytes_array = js_sys::Uint8Array::new(&js_value);
        if bytes_array.length() > 0 {
            let bytes_vec = bytes_array.to_vec();
            if !bytes_vec.is_empty() {
                return NativeAccountPublicKey::decode(&mut &bytes_vec[..])
                    .map(|key| AccountPublicKey { inner: key })
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to decode account public key from Uint8Array: {}",
                            e
                        ))
                    });
            }
        }

        // Try Polkadot.js Codec with toU8a() method
        #[allow(unsafe_code, unused_unsafe)]
        let to_u8a_fn = unsafe { js_sys::Reflect::get(&js_value, &JsValue::from_str("toU8a")) };
        if let Ok(to_u8a_fn) = to_u8a_fn {
            if to_u8a_fn.is_function() {
                if let Ok(bytes_js) = js_sys::Function::from(to_u8a_fn).call0(&js_value) {
                    let bytes_array = js_sys::Uint8Array::new(&bytes_js);
                    if bytes_array.length() > 0 {
                        let bytes_vec = bytes_array.to_vec();
                        return NativeAccountPublicKey::decode(&mut &bytes_vec[..])
                            .map(|key| AccountPublicKey { inner: key })
                            .map_err(|e| {
                                JsValue::from_str(&format!(
                                    "Failed to decode account public key from Codec.toU8a(): {}",
                                    e
                                ))
                            });
                    }
                }
            }
        }

        Err(JsValue::from_str(
            "Invalid AccountPublicKey input. Expected hex string, Uint8Array, Polkadot.js Codec with toU8a() method, or existing AccountPublicKey object"
        ))
    }

    /// Serializes the account public key to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded public key.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = accountKey.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes an account public key from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded account public key data.
    ///
    /// # Returns
    /// The deserialized `AccountPublicKey`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const accountKey = AccountPublicKey.fromBytes(keyBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountPublicKey, JsValue> {
        let inner = NativeAccountPublicKey::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode account public key: {}", e))
        })?;
        Ok(AccountPublicKey { inner })
    }

    /// Exports the account public key as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the account public key.
    ///
    /// # Errors
    /// * Throws an error if serialization to JSON fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Account Public Key:', accountKey.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }

    /// Exports the account public key as a JsValue for interoperability.
    #[wasm_bindgen(js_name = toJs)]
    pub fn to_js(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to serialize AccountPublicKeys to JsValue: {}",
                e
            ))
        })
    }

    /// Import account public key from a JsValue.
    #[wasm_bindgen(js_name = fromJs)]
    pub fn from_js(js_value: JsValue) -> Result<AccountPublicKeys, JsValue> {
        let inner = serde_wasm_bindgen::from_value(js_value).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize AccountPublicKeys from JsValue: {}",
                e
            ))
        })?;
        Ok(AccountPublicKeys::from_native(inner))
    }
}

/// The public key used for encrypting confidential transaction data.
///
/// This key allows others to encrypt settlement leg information and transaction
/// details that only the holder of the corresponding secret key can decrypt.
/// It's essential for maintaining confidentiality in settlements.
///
/// # Example
/// ```javascript
/// // From AccountPublicKeys
/// const encKey = publicKeys.encryptionPublicKey();
///
/// // From hex string or bytes
/// const encKey = new EncryptionPublicKey("0x1234...");
/// const encKey = new EncryptionPublicKey(uint8Array);
///
/// // Use in AssetState
/// const assetState = new AssetState(assetId, [mediatorEncKey], [auditorEncKey]);
/// ```
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionPublicKey {
    pub(crate) inner: NativeEncryptionPublicKey,
}

impl EncryptionPublicKey {
    /// Convert from native EncryptionPublicKey
    pub fn from_native(native: NativeEncryptionPublicKey) -> EncryptionPublicKey {
        EncryptionPublicKey { inner: native }
    }
}

#[wasm_bindgen]
impl EncryptionPublicKey {
    /// Creates a new encryption public key from various input formats.
    ///
    /// # Arguments
    /// * `js_value` - Can be any of:
    ///   - A hex string with or without "0x" prefix (e.g., "0x1234...")
    ///   - A 32-byte `Uint8Array`
    ///   - A Polkadot.js `Codec` object with a `.toU8a()` method
    ///
    /// # Returns
    /// A new `EncryptionPublicKey` object.
    ///
    /// # Errors
    /// * Throws an error if the input format is not recognized or invalid.
    /// * Throws an error if the decoded key is not 32 bytes.
    ///
    /// # Example
    /// ```javascript
    /// // From hex string
    /// const key1 = new EncryptionPublicKey("0x1234...");
    ///
    /// // From Uint8Array
    /// const key2 = new EncryptionPublicKey(new Uint8Array(32));
    ///
    /// // From Polkadot.js Codec
    /// const assetDetail = await api.query.confidentialAssets.dartAssetDetails(assetId);
    /// const mediator = assetDetail.mediators[0]; // Mediator key from chain storage
    /// const key4 = new EncryptionPublicKey(mediator); // Automatically calls toU8a()
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(js_value: JsValue) -> Result<EncryptionPublicKey, JsValue> {
        // Try string (hex format)
        if let Some(js_str) = js_value.as_string() {
            return NativeEncryptionPublicKey::from_str(&js_str)
                .map(|key| EncryptionPublicKey { inner: key })
                .map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to decode encryption public key from hex string: {}",
                        e
                    ))
                });
        }

        // Try Uint8Array (check if it's a valid Uint8Array)
        let bytes_array = js_sys::Uint8Array::new(&js_value);
        if bytes_array.length() > 0 {
            let bytes_vec = bytes_array.to_vec();
            if !bytes_vec.is_empty() {
                return NativeEncryptionPublicKey::decode(&mut &bytes_vec[..])
                    .map(|key| EncryptionPublicKey { inner: key })
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to decode encryption public key from Uint8Array: {}",
                            e
                        ))
                    });
            }
        }

        // Try Polkadot.js Codec with toU8a() method
        #[allow(unsafe_code, unused_unsafe)]
        let to_u8a_fn = unsafe { js_sys::Reflect::get(&js_value, &JsValue::from_str("toU8a")) };
        if let Ok(to_u8a_fn) = to_u8a_fn {
            if to_u8a_fn.is_function() {
                if let Ok(bytes_js) = js_sys::Function::from(to_u8a_fn).call0(&js_value) {
                    let bytes_array = js_sys::Uint8Array::new(&bytes_js);
                    if bytes_array.length() > 0 {
                        let bytes_vec = bytes_array.to_vec();
                        return NativeEncryptionPublicKey::decode(&mut &bytes_vec[..])
                            .map(|key| EncryptionPublicKey { inner: key })
                            .map_err(|e| {
                                JsValue::from_str(&format!(
                                    "Failed to decode encryption public key from Codec.toU8a(): {}",
                                    e
                                ))
                            });
                    }
                }
            }
        }

        Err(JsValue::from_str(
            "Invalid EncryptionPublicKey input. Expected hex string, Uint8Array, Polkadot.js Codec with toU8a() method, or existing EncryptionPublicKey object"
        ))
    }

    /// Serializes the encryption public key to a SCALE-encoded byte array.
    ///
    /// # Returns
    /// A `Uint8Array` containing the SCALE-encoded public key.
    ///
    /// # Example
    /// ```javascript
    /// const bytes = encryptionKey.toBytes();
    /// ```
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Deserializes an encryption public key from a SCALE-encoded byte array.
    ///
    /// # Arguments
    /// * `bytes` - A `Uint8Array` containing SCALE-encoded encryption public key data.
    ///
    /// # Returns
    /// The deserialized `EncryptionPublicKey`.
    ///
    /// # Errors
    /// * Throws an error if the byte array is invalid or corrupted.
    ///
    /// # Example
    /// ```javascript
    /// const encryptionKey = EncryptionPublicKey.fromBytes(keyBytes);
    /// ```
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptionPublicKey, JsValue> {
        let inner = NativeEncryptionPublicKey::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode encryption public key: {}", e))
        })?;
        Ok(EncryptionPublicKey { inner })
    }

    /// Exports the encryption public key as a JSON string for debugging purposes.
    ///
    /// # Returns
    /// A JSON string representation of the encryption public key.
    ///
    /// # Errors
    /// * Throws an error if serialization to JSON fails.
    ///
    /// # Example
    /// ```javascript
    /// console.log('Encryption Public Key:', encryptionKey.toJson());
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }

    /// Exports the encryption public key as a JsValue for interoperability.
    #[wasm_bindgen(js_name = toJs)]
    pub fn to_js(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to serialize EncryptionPublicKey to JsValue: {}",
                e
            ))
        })
    }

    /// Import encryption public key from a JsValue.
    #[wasm_bindgen(js_name = fromJs)]
    pub fn from_js(js_value: JsValue) -> Result<EncryptionPublicKey, JsValue> {
        let inner = serde_wasm_bindgen::from_value(js_value).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize EncryptionPublicKey from JsValue: {}",
                e
            ))
        })?;
        Ok(EncryptionPublicKey { inner })
    }
}

/// Generates a cryptographically secure random 32-byte seed for key generation.
///
/// This function uses the operating system's random number generator to produce
/// a high-quality random seed suitable for generating account keys.
///
/// # Returns
/// A 64-character hexadecimal string representing the 32-byte seed.
///
/// # Errors
/// * May throw an error if the OS random number generator is unavailable (rare).
///
/// # Example
/// ```javascript
/// const seed = generateRandomSeed();
/// console.log('Random seed:', seed); // e.g., "a1b2c3d4..."
///
/// // Use the seed to create account keys
/// const keys = new AccountKeys(seed);
/// ```
#[wasm_bindgen(js_name = generateRandomSeed)]
pub fn generate_random_seed() -> Result<String, JsValue> {
    let mut rng = rand::rngs::OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    Ok(hex::encode(seed))
}
