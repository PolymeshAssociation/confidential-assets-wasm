//! Mnemonic -> `MasterSeed` -> `AccountKeys` derivation.
//!
//! `tests/vectors/derivation-v1.json` is a frozen compatibility contract: a change to it means
//! existing users' keys can no longer be re-derived from their mnemonics.

use polymesh_dart_wasm::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_test::*;

const VECTORS: &str = include_str!("vectors/derivation-v1.json");

const ABANDON_ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const LEGAL_WINNER_TITLE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The official BIP-39 seed for `ABANDON_ABOUT` with passphrase "TREZOR".
const ABANDON_ABOUT_TREZOR_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
/// The official BIP-39 seed for `LEGAL_WINNER_TITLE` with passphrase "TREZOR".
const LEGAL_WINNER_TITLE_TREZOR_SEED: &str = "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87";

const MAX_ACCOUNT: u32 = (1 << 31) - 1;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    mnemonic: String,
    passphrase: String,
    account: u32,
    path: String,
    account_public_key: String,
    encryption_public_key: String,
}

fn hex0x(bytes: Vec<u8>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn public_keys_hex(keys: &AccountKeys) -> (String, String) {
    let public = keys.public_keys();
    (
        hex0x(public.account_public_key().to_bytes()),
        hex0x(public.encryption_public_key().to_bytes()),
    )
}

fn from_mnemonic(phrase: &str, passphrase: &str) -> MasterSeed {
    MasterSeed::from_mnemonic(phrase.to_string(), Some(passphrase.to_string())).unwrap()
}

fn path_for(account: u32) -> String {
    DART_KEY_PATH_TEMPLATE.replace("{account}", &account.to_string())
}

/// Prints the vectors file. Native only (it prints to stdout); run it, then paste the output into
/// `tests/vectors/derivation-v1.json`:
/// `cargo test --release --test wasm_keys_derivation generate_derivation_vectors -- --ignored --nocapture`
#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore]
fn generate_derivation_vectors() {
    let inputs = [
        (ABANDON_ABOUT, ""),
        (ABANDON_ABOUT, "TREZOR"),
        (LEGAL_WINNER_TITLE, "TREZOR"),
    ];
    let mut vectors = Vec::new();
    for (mnemonic, passphrase) in inputs {
        let seed = from_mnemonic(mnemonic, passphrase);
        for account in [0, 1, MAX_ACCOUNT] {
            let keys = seed.derive_account_keys(account as f64).unwrap();
            let (account_public_key, encryption_public_key) = public_keys_hex(&keys);
            vectors.push(Vector {
                mnemonic: mnemonic.to_string(),
                passphrase: passphrase.to_string(),
                account,
                path: path_for(account),
                account_public_key,
                encryption_public_key,
            });
        }
    }
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}

#[wasm_bindgen_test]
fn path_template_is_the_dart_bip44_path() {
    assert_eq!(DART_KEY_PATH_TEMPLATE, "m/44'/595'/{account}'/0/0");
}

#[wasm_bindgen_test]
fn mnemonic_vectors_match() {
    let vectors: Vec<Vector> = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors.len(), 9);
    for v in vectors {
        assert_eq!(v.path, path_for(v.account));
        let keys = from_mnemonic(&v.mnemonic, &v.passphrase)
            .derive_account_keys(v.account as f64)
            .unwrap();
        assert_eq!(
            public_keys_hex(&keys),
            (v.account_public_key, v.encryption_public_key),
            "vector {:?} / {:?} / account {}",
            v.mnemonic,
            v.passphrase,
            v.account
        );
    }
}

/// `fromMnemonic` produces the official BIP-39 seed: the keys match those from `fromBytes` of
/// the seed published in the BIP-39 test vectors.
#[wasm_bindgen_test]
fn mnemonic_seed_matches_official_bip39_vectors() {
    for (mnemonic, seed_hex) in [
        (ABANDON_ABOUT, ABANDON_ABOUT_TREZOR_SEED),
        (LEGAL_WINNER_TITLE, LEGAL_WINNER_TITLE_TREZOR_SEED),
    ] {
        let seed = hex::decode(seed_hex).unwrap();
        assert_eq!(seed.len(), 64);
        let from_bytes = MasterSeed::from_bytes(seed).unwrap();
        let from_phrase = from_mnemonic(mnemonic, "TREZOR");
        for account in [0, 1, MAX_ACCOUNT] {
            assert_eq!(
                public_keys_hex(&from_phrase.derive_account_keys(account as f64).unwrap()),
                public_keys_hex(&from_bytes.derive_account_keys(account as f64).unwrap()),
            );
        }
    }
}

/// `deriveAccountKeys(n)` is DART's `derive_account_keys` at the literal path
/// `m/44'/595'/n'/0/0`, on the official BIP-39 seed.
#[wasm_bindgen_test]
fn derivation_matches_native_dart_at_literal_path() {
    use codec::Encode;
    let seed = format!("0x{}", ABANDON_ABOUT_TREZOR_SEED);
    let native = polymesh_dart::MasterSeed::from_seed(&seed).unwrap();
    let wrapped = from_mnemonic(ABANDON_ABOUT, "TREZOR");
    for (account, path) in [
        (0, "m/44'/595'/0'/0/0"),
        (1, "m/44'/595'/1'/0/0"),
        (MAX_ACCOUNT, "m/44'/595'/2147483647'/0/0"),
    ] {
        let expected = native.derive_account_keys(path).unwrap().public_keys();
        let public = wrapped
            .derive_account_keys(account as f64)
            .unwrap()
            .public_keys();
        assert_eq!(
            public.account_public_key().to_bytes(),
            expected.acct.encode()
        );
        assert_eq!(
            public.encryption_public_key().to_bytes(),
            expected.enc.encode()
        );
    }
}

#[wasm_bindgen_test]
fn mnemonic_and_passphrase_are_normalised() {
    let expected = public_keys_hex(
        &from_mnemonic(ABANDON_ABOUT, "caf\u{e9}")
            .derive_account_keys(0.0)
            .unwrap(),
    );
    // Extra and non-space whitespace in the phrase, and a decomposed passphrase.
    let messy = format!("  {}\n", ABANDON_ABOUT.replace(' ', " \t "));
    let keys = from_mnemonic(&messy, "cafe\u{301}")
        .derive_account_keys(0.0)
        .unwrap();
    assert_eq!(public_keys_hex(&keys), expected);
    // No passphrase is the empty passphrase.
    let none = MasterSeed::from_mnemonic(ABANDON_ABOUT.to_string(), None).unwrap();
    assert_eq!(
        public_keys_hex(&none.derive_account_keys(0.0).unwrap()),
        public_keys_hex(
            &from_mnemonic(ABANDON_ABOUT, "")
                .derive_account_keys(0.0)
                .unwrap()
        ),
    );
}

#[wasm_bindgen_test]
fn bad_checksum_rejected() {
    let bad = ABANDON_ABOUT.replace("about", "abandon");
    assert!(MasterSeed::from_mnemonic(bad, None).is_err());
    // Not in the English wordlist.
    let unknown = ABANDON_ABOUT.replace("about", "aboot");
    assert!(MasterSeed::from_mnemonic(unknown, None).is_err());
    // Wrong word count.
    let short = ABANDON_ABOUT.replacen("abandon ", "", 1);
    assert!(MasterSeed::from_mnemonic(short, None).is_err());
}

#[wasm_bindgen_test]
fn account_index_out_of_range_rejected() {
    let seed = from_mnemonic(ABANDON_ABOUT, "");
    for bad in [
        -1.0,
        2147483648.0,
        4294967296.0,
        0.5,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert!(seed.derive_account_keys(bad).is_err(), "account {}", bad);
    }
    assert!(seed.derive_account_keys(MAX_ACCOUNT as f64).is_ok());
}

#[wasm_bindgen_test]
fn same_mnemonic_different_accounts_differ() {
    let seed = from_mnemonic(ABANDON_ABOUT, "");
    let a = public_keys_hex(&seed.derive_account_keys(0.0).unwrap());
    let b = public_keys_hex(&seed.derive_account_keys(1.0).unwrap());
    assert_ne!(a.0, b.0);
    assert_ne!(a.1, b.1);
    // Deterministic for the same account.
    assert_eq!(a, public_keys_hex(&seed.derive_account_keys(0.0).unwrap()));
}

#[wasm_bindgen_test]
fn generated_mnemonic_has_requested_length_and_valid_checksum() {
    for words in [12, 15, 18, 21, 24] {
        let phrase = generate_mnemonic(Some(words)).unwrap();
        assert_eq!(phrase.split(' ').count(), words as usize);
        assert!(MasterSeed::from_mnemonic(phrase, None).is_ok());
    }
    let default = generate_mnemonic(None).unwrap();
    assert_eq!(default.split(' ').count(), 24);
    assert_ne!(default, generate_mnemonic(None).unwrap());
    for bad in [0, 11, 13, 25, 27] {
        assert!(generate_mnemonic(Some(bad)).is_err(), "words {}", bad);
    }
}

#[wasm_bindgen_test]
fn from_bytes_rejects_short_seed() {
    assert!(MasterSeed::from_bytes(vec![7u8; 31]).is_err());
    assert!(MasterSeed::from_bytes(vec![]).is_err());
    assert!(MasterSeed::from_bytes(vec![7u8; 32]).is_ok());
}

#[wasm_bindgen_test]
fn secret_key_hex_round_trip() {
    let keys = from_mnemonic(ABANDON_ABOUT, "")
        .derive_account_keys(0.0)
        .unwrap();
    let hex = keys.to_secret_key_hex();
    assert!(hex.starts_with("0x"));
    assert_eq!(hex, hex.to_lowercase());

    let decoded = AccountKeys::from_secret_key_hex(hex.clone()).unwrap();
    assert_eq!(public_keys_hex(&decoded), public_keys_hex(&keys));
    assert_eq!(decoded.to_secret_key_hex(), hex);

    // Accepts a `0X` prefix and upper-case digits.
    let upper = format!("0X{}", hex[2..].to_uppercase());
    let decoded = AccountKeys::from_secret_key_hex(upper).unwrap();
    assert_eq!(public_keys_hex(&decoded), public_keys_hex(&keys));

    // Strict: trailing bytes and truncation are rejected.
    assert!(AccountKeys::from_secret_key_hex(format!("{}00", hex)).is_err());
    assert!(AccountKeys::from_secret_key_hex(hex[..hex.len() - 2].to_string()).is_err());
    assert!(AccountKeys::from_secret_key_hex("0xzz".to_string()).is_err());
}
