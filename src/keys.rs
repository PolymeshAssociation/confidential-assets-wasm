use codec::{Decode, Encode};
use polymesh_dart::{
    curve_tree::get_account_curve_tree_parameters,
    AccountAssetRegistrationProof as NativeAccountAssetRegistrationProof,
    AccountKeys as NativeAccountKeys, AccountPublicKey as NativeAccountPublicKey,
    AccountPublicKeys as NativeAccountPublicKeys,
    AccountRegistrationProof as NativeAccountRegistrationProof,
    EncryptionPublicKey as NativeEncryptionPublicKey,
};
use rand::RngCore as _;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use wasm_bindgen::prelude::*;

use crate::{jsvalue_to_identity_id, AccountAssetRegistrationProof, AccountAssetState};

/// Account keys containing both the account secret key and encryption secret key.
/// This type is used for operations requiring the private keys.
#[wasm_bindgen]
pub struct AccountKeys {
    pub(crate) inner: NativeAccountKeys,
}

#[wasm_bindgen]
impl AccountKeys {
    /// Generate new account keys from a random seed string.
    /// The seed should be a hexadecimal string.
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

    /// Create account keys from a seed string (convenience method that accepts any string).
    /// The string will be hashed to create a deterministic seed.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &str) -> Result<AccountKeys, JsValue> {
        let inner = NativeAccountKeys::from_seed(seed)
            .map_err(|e| JsValue::from_str(&format!("Failed to create keys from seed: {}", e)))?;
        Ok(AccountKeys { inner })
    }

    /// Export account keys as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import account keys from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountKeys, JsValue> {
        let inner = NativeAccountKeys::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode account keys: {}", e)))?;
        Ok(AccountKeys { inner })
    }

    /// Get the public keys corresponding to these account keys
    #[wasm_bindgen(js_name = publicKeys)]
    pub fn public_keys(&self) -> AccountPublicKeys {
        AccountPublicKeys {
            inner: self.inner.public_keys(),
        }
    }

    /// Generate an account registration proof for the account keys.  The proof needs the identity id that the account keys will be linked to.
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

    /// Generate an account asset registration proof for the account keys and a specific asset.  The proof needs the asset id and identity id.
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

/// An account registration proof.
#[wasm_bindgen]
pub struct AccountRegistrationProof {
    pub(crate) inner: NativeAccountRegistrationProof<()>,
}

#[wasm_bindgen]
impl AccountRegistrationProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountRegistrationProof, JsValue> {
        let inner = NativeAccountRegistrationProof::<()>::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode registration proof: {}", e))
        })?;
        Ok(AccountRegistrationProof { inner })
    }
}

/// The Account asset registration proof and resulting account asset state
/// generated when registering an account for a specific asset.
#[wasm_bindgen]
pub struct AccountAssetRegistration {
    pub(crate) proof: NativeAccountAssetRegistrationProof,
    pub(crate) state: AccountAssetState,
}

#[wasm_bindgen]
impl AccountAssetRegistration {
    /// Get the registration proof
    #[wasm_bindgen(js_name = getProof)]
    pub fn get_proof(&self) -> AccountAssetRegistrationProof {
        AccountAssetRegistrationProof {
            inner: self.proof.clone(),
        }
    }

    /// Get the registration proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = getProofBytes)]
    pub fn get_proof_bytes(&self) -> Vec<u8> {
        self.proof.encode()
    }

    /// Get the resulting account asset state
    #[wasm_bindgen(js_name = getAccountAssetState)]
    pub fn get_account_asset_state(&self) -> AccountAssetState {
        self.state.clone()
    }
}

/// Public keys for an account (account public key and encryption public key)
#[wasm_bindgen]
pub struct AccountPublicKeys {
    inner: NativeAccountPublicKeys,
}

#[wasm_bindgen]
impl AccountPublicKeys {
    /// Export public keys as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import public keys from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountPublicKeys, JsValue> {
        let inner = NativeAccountPublicKeys::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode public keys: {}", e)))?;
        Ok(AccountPublicKeys { inner })
    }

    /// Get the account public key component
    #[wasm_bindgen(js_name = accountPublicKey)]
    pub fn account_public_key(&self) -> AccountPublicKey {
        AccountPublicKey {
            inner: self.inner.acct.clone(),
        }
    }

    /// Get the encryption public key component
    #[wasm_bindgen(js_name = encryptionPublicKey)]
    pub fn encryption_public_key(&self) -> EncryptionPublicKey {
        EncryptionPublicKey {
            inner: self.inner.enc.clone(),
        }
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Account public key (used for account commitments and proofs)
#[wasm_bindgen]
pub struct AccountPublicKey {
    pub(crate) inner: NativeAccountPublicKey,
}

#[wasm_bindgen]
impl AccountPublicKey {
    /// New account public key from js value (32 byte array, or hex string)
    #[wasm_bindgen(constructor)]
    pub fn new(js_value: JsValue) -> Result<AccountPublicKey, JsValue> {
        let key = if let Some(js_str) = js_value.as_string() {
            NativeAccountPublicKey::from_str(&js_str)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode mediator key: {}", e)))?
        } else {
            let bytes = js_sys::Uint8Array::from(js_value).to_vec();
            NativeAccountPublicKey::decode(&mut &bytes[..])
                .map_err(|e| JsValue::from_str(&format!("Failed to decode mediator key: {}", e)))?
        };

        Ok(AccountPublicKey { inner: key })
    }

    /// Export account public key as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import account public key from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<AccountPublicKey, JsValue> {
        let inner = NativeAccountPublicKey::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode account public key: {}", e))
        })?;
        Ok(AccountPublicKey { inner })
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Encryption public key (used for encrypting settlement leg information)
#[wasm_bindgen]
pub struct EncryptionPublicKey {
    pub(crate) inner: NativeEncryptionPublicKey,
}

#[wasm_bindgen]
impl EncryptionPublicKey {
    /// New encryption public key from js value (32 byte array, or hex string)
    #[wasm_bindgen(constructor)]
    pub fn new(js_value: JsValue) -> Result<EncryptionPublicKey, JsValue> {
        let key = if let Some(js_str) = js_value.as_string() {
            NativeEncryptionPublicKey::from_str(&js_str)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode mediator key: {}", e)))?
        } else {
            let bytes = js_sys::Uint8Array::from(js_value).to_vec();
            NativeEncryptionPublicKey::decode(&mut &bytes[..])
                .map_err(|e| JsValue::from_str(&format!("Failed to decode mediator key: {}", e)))?
        };

        Ok(EncryptionPublicKey { inner: key })
    }

    /// Export encryption public key as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import encryption public key from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptionPublicKey, JsValue> {
        let inner = NativeEncryptionPublicKey::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode encryption public key: {}", e))
        })?;
        Ok(EncryptionPublicKey { inner })
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Generate a random 32-byte seed for key generation
/// Returns a hex-encoded string
#[wasm_bindgen(js_name = generateRandomSeed)]
pub fn generate_random_seed() -> Result<String, JsValue> {
    let mut rng = rand::rngs::OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    Ok(hex::encode(seed))
}
