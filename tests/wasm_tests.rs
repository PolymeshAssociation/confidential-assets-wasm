use polymesh_dart_wasm::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_public_keys_components() {
    let mnemonic = generate_mnemonic(None).unwrap();
    let keys = MasterSeed::from_mnemonic(mnemonic, None)
        .unwrap()
        .derive_account_keys(0.0)
        .unwrap();
    let pub_keys = keys.public_keys();

    // Should be able to get individual components
    let account_pub_key = pub_keys.account_public_key();
    let encryption_pub_key = pub_keys.encryption_public_key();

    // Should be able to export them
    let _account_bytes = account_pub_key.to_bytes();
    let _encryption_bytes = encryption_pub_key.to_bytes();
}
