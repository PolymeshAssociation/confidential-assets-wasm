use codec::{Decode, Encode};
use polymesh_dart::{
    AccountKeys as NativeAccountKeys, AccountPublicKeys as NativeAccountPublicKeys,
};
use polymesh_dart::{
    AccountPublicKey as NativeAccountPublicKey, EncryptionPublicKey as NativeEncryptionPublicKey,
};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use wasm_bindgen::prelude::*;

/// Account keys containing both the account secret key and encryption secret key.
/// This type is used for operations requiring the private keys.
#[wasm_bindgen]
pub struct AccountKeys {
    inner: NativeAccountKeys,
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
    use rand_core::RngCore;
    let mut rng = ChaChaRng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    Ok(hex::encode(seed))
}
