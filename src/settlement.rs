use codec::{Decode, Encode};
use polymesh_dart::{
    AssetId, Balance, LegBuilder as NativeLegBuilder, LegEncrypted as NativeLegEncrypted,
    MediatorAffirmationProof as NativeMediatorAffirmationProof,
    ReceiverAffirmationProof as NativeReceiverAffirmationProof,
    ReceiverClaimProof as NativeReceiverClaimProof,
    SenderAffirmationProof as NativeSenderAffirmationProof,
    SenderCounterUpdateProof as NativeSenderCounterUpdateProof,
    SenderReversalProof as NativeSenderReversalProof, SettlementBuilder as NativeSettlementBuilder,
    SettlementProof as NativeSettlementProof,
};
use wasm_bindgen::prelude::*;

use crate::{
    bytes_to_jsvalue, jsvalue_to_bytes, AccountPublicKeys, AssetLeafPath, AssetState, AssetTreeRoot,
};

/// A settlement builder to create settlements
#[wasm_bindgen]
pub struct SettlementBuilder {
    pub(crate) inner: NativeSettlementBuilder,
}

#[wasm_bindgen]
impl SettlementBuilder {
    /// Create a new settlement builder
    #[wasm_bindgen(constructor)]
    pub fn new(
        memo: JsValue,
        block_number: u32,
        root: AssetTreeRoot,
    ) -> Result<SettlementBuilder, JsValue> {
        let memo = jsvalue_to_bytes(&memo)?;
        Ok(SettlementBuilder {
            inner: NativeSettlementBuilder::new_root(&memo, block_number, root.root),
        })
    }

    /// Add a leg to the settlement
    #[wasm_bindgen(js_name = addLeg)]
    pub fn add_leg(&mut self, leg: &LegBuilder) {
        self.inner.add_leg(leg.to_native());
    }

    /// Add an asset leaf path.
    #[wasm_bindgen(js_name = addAssetPath)]
    pub fn add_asset_path(
        &mut self,
        asset_id: AssetId,
        path: AssetLeafPath,
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

    /// Build the settlement proof.
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

/// A settlement leg containing asset transfer details
#[wasm_bindgen(getter_with_clone)]
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
    /// Create a leg.
    ///
    /// # Arguments
    /// - `sender`: The sender's account public keys.  Type `AccountPublicKeys`.
    /// - `receiver`: The receiver's account public keys.  Type `AccountPublicKeys`.
    /// - `asset`: The asset state.  Type `AssetState`.
    /// - `amount`: The amount to transfer.  Type `Balance`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        sender: AccountPublicKeys,
        receiver: AccountPublicKeys,
        asset: AssetState,
        amount: Balance,
    ) -> LegBuilder {
        LegBuilder {
            sender,
            receiver,
            asset,
            amount,
        }
    }
}

/// Encrypted settlement leg
#[wasm_bindgen]
pub struct LegEncrypted {
    pub(crate) inner: NativeLegEncrypted,
}

#[wasm_bindgen]
impl LegEncrypted {
    /// Export encrypted leg as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import encrypted leg from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<LegEncrypted, JsValue> {
        let inner = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode encrypted leg: {}", e)))?;
        Ok(LegEncrypted { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<LegEncrypted, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Settlement proof
#[wasm_bindgen]
pub struct SettlementProof {
    pub(crate) inner: NativeSettlementProof,
}

#[wasm_bindgen]
impl SettlementProof {
    /// Export settlement proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import settlement proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SettlementProof, JsValue> {
        let inner = Decode::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode settlement proof: {}", e)))?;
        Ok(SettlementProof { inner })
    }

    /// Get the memo.
    #[wasm_bindgen(js_name = getMemo)]
    pub fn get_memo(&self) -> JsValue {
        bytes_to_jsvalue(&self.inner.memo)
    }

    /// Get the block number.
    ///
    /// This is the block number of the root used for the asset leaf paths.
    #[wasm_bindgen(js_name = getBlockNumber)]
    pub fn get_block_number(&self) -> u32 {
        self.inner.root_block
    }

    /// Get the number of legs.
    #[wasm_bindgen(js_name = getLegCount)]
    pub fn get_leg_count(&self) -> usize {
        self.inner.legs.len()
    }

    /// Get the encrypted legs.
    #[wasm_bindgen(js_name = getLegs)]
    pub fn get_legs(&self) -> Vec<LegEncrypted> {
        self.inner
            .legs
            .iter()
            .map(|proof| LegEncrypted {
                inner: proof.leg_enc.clone(),
            })
            .collect()
    }
}

/// Proof of sender affirmation
#[wasm_bindgen]
pub struct SenderAffirmationProof {
    pub(crate) inner: NativeSenderAffirmationProof,
}

#[wasm_bindgen]
impl SenderAffirmationProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SenderAffirmationProof, JsValue> {
        let inner = NativeSenderAffirmationProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode sender affirmation proof: {}", e))
        })?;
        Ok(SenderAffirmationProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<SenderAffirmationProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of receiver affirmation
#[wasm_bindgen]
pub struct ReceiverAffirmationProof {
    pub(crate) inner: NativeReceiverAffirmationProof,
}

#[wasm_bindgen]
impl ReceiverAffirmationProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<ReceiverAffirmationProof, JsValue> {
        let inner = NativeReceiverAffirmationProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode receiver affirmation proof: {}",
                e
            ))
        })?;
        Ok(ReceiverAffirmationProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<ReceiverAffirmationProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of receiver claim
#[wasm_bindgen]
pub struct ReceiverClaimProof {
    pub(crate) inner: NativeReceiverClaimProof,
}

#[wasm_bindgen]
impl ReceiverClaimProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<ReceiverClaimProof, JsValue> {
        let inner = NativeReceiverClaimProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode receiver claim proof: {}", e))
        })?;
        Ok(ReceiverClaimProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<ReceiverClaimProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of sender counter update
#[wasm_bindgen]
pub struct SenderCounterUpdateProof {
    pub(crate) inner: NativeSenderCounterUpdateProof,
}

#[wasm_bindgen]
impl SenderCounterUpdateProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SenderCounterUpdateProof, JsValue> {
        let inner = NativeSenderCounterUpdateProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode sender counter update proof: {}",
                e
            ))
        })?;
        Ok(SenderCounterUpdateProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<SenderCounterUpdateProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of sender reversal
#[wasm_bindgen]
pub struct SenderReversalProof {
    pub(crate) inner: NativeSenderReversalProof,
}

#[wasm_bindgen]
impl SenderReversalProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SenderReversalProof, JsValue> {
        let inner = NativeSenderReversalProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode sender reversal proof: {}", e))
        })?;
        Ok(SenderReversalProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<SenderReversalProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

/// Proof of mediator affirmation
#[wasm_bindgen]
pub struct MediatorAffirmationProof {
    pub(crate) inner: NativeMediatorAffirmationProof,
}

#[wasm_bindgen]
impl MediatorAffirmationProof {
    /// Export proof as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import proof from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<MediatorAffirmationProof, JsValue> {
        let inner = NativeMediatorAffirmationProof::decode(&mut &bytes[..]).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode mediator affirmation proof: {}",
                e
            ))
        })?;
        Ok(MediatorAffirmationProof { inner })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<MediatorAffirmationProof, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}
