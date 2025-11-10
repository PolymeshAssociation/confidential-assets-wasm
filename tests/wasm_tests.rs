use polymesh_dart_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_generate_random_seed() {
    let seed1 = generate_random_seed().unwrap();
    let seed2 = generate_random_seed().unwrap();

    // Seeds should be 64 characters (32 bytes in hex)
    assert_eq!(seed1.len(), 64);
    assert_eq!(seed2.len(), 64);

    // Seeds should be different
    assert_ne!(seed1, seed2);
}

#[wasm_bindgen_test]
fn test_account_keys_creation() {
    let seed = generate_random_seed().unwrap();
    let keys = AccountKeys::new(&seed).unwrap();

    // Should be able to get public keys
    let pub_keys = keys.public_keys();

    // Should be able to export and re-import
    let bytes = keys.to_bytes();
    let reimported = AccountKeys::from_bytes(&bytes).unwrap();

    // Public keys should match
    let pub_keys2 = reimported.public_keys();
    assert_eq!(pub_keys.to_bytes(), pub_keys2.to_bytes());
}

#[wasm_bindgen_test]
fn test_account_keys_from_seed() {
    let seed_str = "test-seed-123";
    let keys1 = AccountKeys::from_seed(seed_str).unwrap();
    let keys2 = AccountKeys::from_seed(seed_str).unwrap();

    // Same seed should produce same keys
    assert_eq!(keys1.to_bytes(), keys2.to_bytes());
}

#[wasm_bindgen_test]
fn test_public_keys_components() {
    let seed = generate_random_seed().unwrap();
    let keys = AccountKeys::new(&seed).unwrap();
    let pub_keys = keys.public_keys();

    // Should be able to get individual components
    let account_pub_key = pub_keys.account_public_key();
    let encryption_pub_key = pub_keys.encryption_public_key();

    // Should be able to export them
    let _account_bytes = account_pub_key.to_bytes();
    let _encryption_bytes = encryption_pub_key.to_bytes();
}

#[wasm_bindgen_test]
fn test_asset_state_creation() {
    let asset_id = 42;
    let mediators = vec![];
    let auditors = vec![];

    let asset_state = AssetState::new(asset_id, mediators, auditors).unwrap();

    assert_eq!(asset_state.asset_id(), asset_id);
    assert_eq!(asset_state.mediator_count(), 0);
    assert_eq!(asset_state.auditor_count(), 0);

    // Should be able to export and re-import
    let bytes = asset_state.to_bytes();
    let reimported = AssetState::from_bytes(&bytes).unwrap();
    assert_eq!(reimported.asset_id(), asset_id);
}

#[wasm_bindgen_test]
fn test_settlement_ref_hex() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xAB;
    bytes[31] = 0xCD;

    let settlement_ref = SettlementRef::from_bytes(&bytes).unwrap();
    let hex = settlement_ref.to_hex();

    // Should start with ab and end with cd
    assert!(hex.starts_with("ab"));
    assert!(hex.ends_with("cd"));

    // Should be able to round-trip through hex
    let reimported = SettlementRef::from_hex(&hex).unwrap();
    assert_eq!(settlement_ref.to_bytes(), reimported.to_bytes());
}
