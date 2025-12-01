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
