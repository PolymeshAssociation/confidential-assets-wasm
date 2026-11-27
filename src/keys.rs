use bip39::{Language, Mnemonic};
use codec::{Decode, DecodeAll, Encode};
use polymesh_dart::{
    curve_tree::get_account_curve_tree_parameters,
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountKeys as NativeAccountKeys, AccountPublicKey as NativeAccountPublicKey,
    AccountPublicKeys as NativeAccountPublicKeys,
    AccountRegistrationProof as NativeAccountRegistrationProof, AssetId,
    EncryptionKeyPair as NativeEncryptionKeyPair, EncryptionPublicKey as NativeEncryptionPublicKey,
    LegId, LegRef, LegRole, LegRoleKind, MasterSeed as NativeMasterSeed,
    MediatorAffirmationProof as NativeMediatorAffirmationProof,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use wasm_bindgen::prelude::*;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    jsvalue_to_balance, jsvalue_to_identity_id, jsvalue_to_settlement_ref,
    AccountAssetRegistration, AccountAssetState, MediatorAffirmationProof, SettlementLegEncrypted,
};

/// The DART account key derivation path. `{account}` stands for the account index.
pub const DART_KEY_PATH_TEMPLATE: &str = "m/44'/595'/{account}'/0/0";

/// The number of words `generateMnemonic` uses when none is given.
const DEFAULT_MNEMONIC_WORDS: u32 = 24;

/// Accounts are hardened BIP-32 indices, so they must be below 2^31.
const ACCOUNT_LIMIT: f64 = (1u64 << 31) as f64;

/// Generates a new random BIP-39 mnemonic from the English wordlist.
///
/// # Arguments
/// * `words` - The number of words: 12, 15, 18, 21 or 24. Defaults to 24.
///
/// # Returns
/// The mnemonic, its words separated by single spaces.
///
/// # Errors
/// * Throws an error if `words` isn't 12, 15, 18, 21 or 24.
/// * Throws an error if the system random number generator is unavailable.
///
/// # Example
/// ```javascript
/// const mnemonic = generateMnemonic();
/// const masterSeed = MasterSeed.fromMnemonic(mnemonic);
/// ```
#[wasm_bindgen(js_name = generateMnemonic)]
pub fn generate_mnemonic(words: Option<u32>) -> Result<String, JsValue> {
    let words = words.unwrap_or(DEFAULT_MNEMONIC_WORDS);
    if !matches!(words, 12 | 15 | 18 | 21 | 24) {
        return Err(JsValue::from_str(&format!(
            "Mnemonic word count must be 12, 15, 18, 21 or 24, not {}",
            words
        )));
    }
    // Each 3 words carry 4 bytes of entropy (plus checksum bits).
    let len = words as usize / 3 * 4;
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut entropy[..len])
        .map_err(|e| JsValue::from_str(&format!("Failed to generate randomness: {}", e)))?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy[..len])
        .map_err(|e| JsValue::from_str(&format!("Failed to generate mnemonic: {}", e)))?;
    Ok(mnemonic.to_string())
}

/// NFKD-normalises `s` into a buffer that is zeroized on drop.
fn nfkd(s: &str) -> Zeroizing<String> {
    let mut cow = Cow::Borrowed(s);
    Mnemonic::normalize_utf8_cow(&mut cow);
    Zeroizing::new(cow.into_owned())
}

/// `0x` + the lowercase hex of `bytes`, without leaving an unzeroized intermediate copy.
fn secret_to_hex(bytes: &[u8]) -> String {
    let encoded = Zeroizing::new(hex::encode(bytes));
    let mut out = String::with_capacity(2 + encoded.len());
    out.push_str("0x");
    out.push_str(&encoded);
    out
}

/// The seed that all of a wallet's DART account keys are derived from.
///
/// Create it from a BIP-39 mnemonic with `MasterSeed.fromMnemonic`, then derive each account's
/// keys with `deriveAccountKeys(account)`. Call `clear()` when it's no longer needed.
///
/// # Example
/// ```javascript
/// const mnemonic = generateMnemonic();
/// const masterSeed = MasterSeed.fromMnemonic(mnemonic);
/// const keys = masterSeed.deriveAccountKeys(0);
/// masterSeed.clear();
/// ```
#[wasm_bindgen]
pub struct MasterSeed {
    pub(crate) inner: NativeMasterSeed,
}

#[wasm_bindgen]
impl MasterSeed {
    /// Creates a MasterSeed from a BIP-39 mnemonic (English wordlist).
    ///
    /// The phrase and passphrase are NFKD-normalised and the phrase's whitespace is ignored, per
    /// BIP-39. The 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) is the master seed.
    ///
    /// # Arguments
    /// * `phrase` - A 12, 15, 18, 21 or 24-word mnemonic.
    /// * `passphrase` - The optional BIP-39 passphrase. Defaults to the empty string.
    ///
    /// # Errors
    /// * Throws an error if a word isn't in the English wordlist, the word count is wrong, or
    ///   the checksum doesn't match.
    ///
    /// # Example
    /// ```javascript
    /// const masterSeed = MasterSeed.fromMnemonic(mnemonic, "optional passphrase");
    /// ```
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(
        phrase: String,
        passphrase: Option<String>,
    ) -> Result<MasterSeed, JsValue> {
        let phrase = Zeroizing::new(phrase);
        let passphrase = Zeroizing::new(passphrase.unwrap_or_default());
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &nfkd(&phrase))
            .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {}", e)))?;
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(&nfkd(&passphrase)));
        Self::from_seed_bytes(&seed[..])
    }

    /// Creates a MasterSeed from raw seed bytes. For tests and advanced hosts; wallets should use
    /// `fromMnemonic`.
    ///
    /// # Arguments
    /// * `seed` - At least 32 bytes.
    ///
    /// # Errors
    /// * Throws an error if the seed is shorter than 32 bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(seed: Vec<u8>) -> Result<MasterSeed, JsValue> {
        // Owned, so the copy of the seed in wasm memory is zeroized.
        Self::from_seed_bytes(&Zeroizing::new(seed))
    }

    fn from_seed_bytes(seed: &[u8]) -> Result<MasterSeed, JsValue> {
        let seed_hex = Zeroizing::new(secret_to_hex(seed));
        let inner = NativeMasterSeed::from_seed(&seed_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid master seed: {}", e)))?;
        Ok(MasterSeed { inner })
    }

    /// The derivation path template, `m/44'/595'/{account}'/0/0`.
    #[wasm_bindgen(getter = DART_KEY_PATH_TEMPLATE)]
    pub fn dart_key_path_template() -> String {
        DART_KEY_PATH_TEMPLATE.to_string()
    }

    /// Derives the keys of an account, at path `m/44'/595'/{account}'/0/0`.
    ///
    /// # Arguments
    /// * `account` - The account index, an integer from 0 to 2^31 - 1.
    ///
    /// # Returns
    /// The account's `AccountKeys`. The same seed and account always give the same keys.
    ///
    /// # Errors
    /// * Throws an error if `account` isn't an integer from 0 to 2^31 - 1.
    ///
    /// # Example
    /// ```javascript
    /// const keys = masterSeed.deriveAccountKeys(0);
    /// ```
    #[wasm_bindgen(js_name = deriveAccountKeys)]
    pub fn derive_account_keys(&self, account: f64) -> Result<AccountKeys, JsValue> {
        if account.fract() != 0.0 || !(0.0..ACCOUNT_LIMIT).contains(&account) {
            return Err(JsValue::from_str(&format!(
                "Account index must be an integer from 0 to 2^31 - 1, not {}",
                account
            )));
        }
        let path = DART_KEY_PATH_TEMPLATE.replace("{account}", &(account as u32).to_string());
        let inner = self
            .inner
            .derive_account_keys(&path)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive account keys: {}", e)))?;
        Ok(AccountKeys { inner })
    }

    /// Clears the seed from memory by zeroing it out.
    ///
    /// The `MasterSeed` instance can't be used after calling this method.
    #[wasm_bindgen(js_name = clear)]
    pub fn clear(mut self) {
        self.inner.zeroize();
    }
}

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
/// // Derive from a BIP-39 mnemonic
/// const keys = MasterSeed.fromMnemonic(mnemonic).deriveAccountKeys(0);
///
/// // Get public keys for sharing
/// const publicKeys = keys.publicKeys();
/// ```
#[wasm_bindgen]
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AccountKeys {
    pub(crate) inner: NativeAccountKeys,
}

#[wasm_bindgen]
impl AccountKeys {
    /// Returns the private key: `0x` + the SCALE encoding of these `AccountKeys`.
    ///
    /// **Treat it like a seed.** Anyone holding it controls the account.
    ///
    /// # Example
    /// ```javascript
    /// const secret = keys.toSecretKeyHex();
    /// const sameKeys = AccountKeys.fromSecretKeyHex(secret);
    /// ```
    #[wasm_bindgen(js_name = toSecretKeyHex)]
    pub fn to_secret_key_hex(&self) -> String {
        secret_to_hex(&Zeroizing::new(self.inner.encode()))
    }

    /// Restores account keys from the private key returned by `toSecretKeyHex()`.
    ///
    /// # Arguments
    /// * `hex` - The private key hex, with or without a `0x` prefix.
    ///
    /// # Errors
    /// * Throws an error if the hex is invalid, or isn't exactly one SCALE-encoded `AccountKeys`
    ///   (trailing bytes are rejected).
    #[wasm_bindgen(js_name = fromSecretKeyHex)]
    pub fn from_secret_key_hex(hex: String) -> Result<AccountKeys, JsValue> {
        let hex = Zeroizing::new(hex);
        let digits = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(&hex);
        // The error leaves out the decoder's message, which can quote the secret.
        let bytes = Zeroizing::new(
            hex::decode(digits).map_err(|_| JsValue::from_str("Invalid secret key hex"))?,
        );
        let inner = NativeAccountKeys::decode_all(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;
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

        let params = get_account_curve_tree_parameters();

        let (proof, state) = NativeAccountAssetRegistrationProof::new(
            &mut rng,
            &self.inner,
            asset_id,
            0,
            &did.0[..],
            &params,
            None,
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
            .try_decrypt_with_key(
                &self.inner.enc,
                None,
                Some(&self.inner.acct.public),
                None,
                None,
            )
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
            LegRole {
                kind: LegRoleKind::Mediator,
                index: Some(idx),
            } => idx,
            _ => {
                return Err(JsValue::from_str(
                    "Only mediators can affirm or reject settlement legs",
                ))
            }
        };

        let med_enc = leg_enc
            .mediator_encryption(key_index)
            .map_err(|e| JsValue::from_str(&format!("Failed to get mediator encryption: {}", e)))?;
        let proof = NativeMediatorAffirmationProof::new(
            &mut rng,
            &leg_ref,
            &med_enc,
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

    /// Clears the secret keys from memory by zeroing them out.
    ///
    /// The `AccountKeys` instance can't be used after calling this method.
    #[wasm_bindgen(js_name = clear)]
    pub fn clear(mut self) {
        self.inner.zeroize();
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
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKeyPair {
    pub(crate) inner: NativeEncryptionKeyPair,
}

#[wasm_bindgen]
impl EncryptionKeyPair {
    /// Clears the encryption secret key from memory by zeroing it out.
    ///
    /// The `EncryptionKeyPair` instance can't be used after calling this method.
    #[wasm_bindgen(js_name = clear)]
    pub fn clear(mut self) {
        self.inner.zeroize();
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
                let native =
                    NativeAccountPublicKeys::decode_all(&mut &bytes_vec[..]).map_err(|e| {
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
        let inner = NativeAccountPublicKeys::decode_all(&mut &bytes[..])
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
    /// const assetKeys = (await api.query.confidentialAssets.keys(assetId)).unwrap();
    /// const mediator = [...assetKeys.mediators][0]; // Mediator key from chain storage
    /// const key4 = new AccountPublicKey(mediator); // Automatically calls toU8a()
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
                return NativeAccountPublicKey::decode_all(&mut &bytes_vec[..])
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
                        return NativeAccountPublicKey::decode_all(&mut &bytes_vec[..])
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
        let inner = NativeAccountPublicKey::decode_all(&mut &bytes[..]).map_err(|e| {
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
/// const assetState = new AssetState(assetId, {
///     encKeys: [auditorEncKey.toJs(), mediatorEncKey.toJs()],
///     mediators: [mediatorAccountKey.toJs()],
/// });
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
    /// const assetKeys = (await api.query.confidentialAssets.keys(assetId)).unwrap();
    /// const encKey = [...assetKeys.encKeys][0]; // Auditor or mediator key from chain storage
    /// const key4 = new EncryptionPublicKey(encKey); // Automatically calls toU8a()
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
                return NativeEncryptionPublicKey::decode_all(&mut &bytes_vec[..])
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
                        return NativeEncryptionPublicKey::decode_all(&mut &bytes_vec[..])
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
        let inner = NativeEncryptionPublicKey::decode_all(&mut &bytes[..]).map_err(|e| {
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
