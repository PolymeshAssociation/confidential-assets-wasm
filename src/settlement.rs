use codec::{Decode, Encode};
use polymesh_dart::{AssetId, Balance, LegId};
use polymesh_dart::{
    Leg as NativeLeg, LegEncrypted as NativeLegEncrypted, LegRef as NativeLegRef,
    MediatorAffirmationProof as NativeMediatorAffirmationProof,
    ReceiverAffirmationProof as NativeReceiverAffirmationProof,
    ReceiverClaimProof as NativeReceiverClaimProof,
    SenderAffirmationProof as NativeSenderAffirmationProof,
    SenderCounterUpdateProof as NativeSenderCounterUpdateProof,
    SenderReversalProof as NativeSenderReversalProof, SettlementRef as NativeSettlementRef,
};
use wasm_bindgen::prelude::*;

/// A settlement leg containing asset transfer details
#[wasm_bindgen]
pub struct Leg {
    pub(crate) inner: NativeLeg,
}

#[wasm_bindgen]
impl Leg {
    /// Export leg as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import leg from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Leg, JsValue> {
        let inner = NativeLeg::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode leg: {}", e)))?;
        Ok(Leg { inner })
    }

    /// Get the asset ID being transferred
    #[wasm_bindgen(js_name = assetId)]
    pub fn asset_id(&self) -> AssetId {
        self.inner.asset_id()
    }

    /// Get the transfer amount
    #[wasm_bindgen(js_name = amount)]
    pub fn amount(&self) -> Balance {
        self.inner.amount()
    }

    /// Export as JSON string (for debugging)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
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

/// Reference to a specific leg in a settlement
#[wasm_bindgen]
pub struct LegRef {
    pub(crate) inner: NativeLegRef,
}

#[wasm_bindgen]
impl LegRef {
    /// Create a new leg reference
    #[wasm_bindgen(constructor)]
    pub fn new(settlement_ref: &SettlementRef, leg_id: LegId) -> LegRef {
        LegRef {
            inner: NativeLegRef::new(settlement_ref.inner.clone(), leg_id as u8),
        }
    }

    /// Export leg ref as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Import leg ref from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<LegRef, JsValue> {
        let inner = NativeLegRef::decode(&mut &bytes[..])
            .map_err(|e| JsValue::from_str(&format!("Failed to decode leg ref: {}", e)))?;
        Ok(LegRef { inner })
    }
}

/// Reference to a settlement
#[wasm_bindgen]
pub struct SettlementRef {
    pub(crate) inner: NativeSettlementRef,
}

#[wasm_bindgen]
impl SettlementRef {
    /// Export settlement ref as a SCALE-encoded byte array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.0.to_vec()
    }

    /// Import settlement ref from a SCALE-encoded byte array
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<SettlementRef, JsValue> {
        if bytes.len() != 32 {
            return Err(JsValue::from_str("Settlement ref must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(SettlementRef {
            inner: NativeSettlementRef(arr),
        })
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<SettlementRef, JsValue> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex string: {}", e)))?;
        Self::from_bytes(&bytes)
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
