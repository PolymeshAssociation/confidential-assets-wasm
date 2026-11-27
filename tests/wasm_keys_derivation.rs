//! Mnemonic -> `MasterSeed` -> `AccountKeys` derivation.
//!
//! `tests/vectors/derivation-v1.json` is a frozen compatibility contract: a change to it means
//! existing users' keys can no longer be re-derived from their mnemonics.

use polymesh_dart_wasm::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

const VECTORS: &str = include_str!("vectors/derivation-v1.json");

const ABANDON_ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const LEGAL_WINNER_TITLE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The official BIP-39 seed for `ABANDON_ABOUT` with passphrase "TREZOR".
const ABANDON_ABOUT_TREZOR_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
/// The official BIP-39 seed for `LEGAL_WINNER_TITLE` with passphrase "TREZOR".
const LEGAL_WINNER_TITLE_TREZOR_SEED: &str = "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87";

/// A passphrase that NFKD changes, written in NFC: a precomposed "é" (U+00E9, which NFKD
/// decomposes to "e" U+0301) and the ligature "ﬁ" (U+FB01, which NFKD maps to "fi").
const NFKD_PASSPHRASE: &str = "caf\u{e9} \u{fb01}";

const MAX_ACCOUNT: u32 = (1 << 31) - 1;

/// `sig_key_gen` and `enc_key_gen`, compressed (`docs/KEY_FILE_FORMAT.md` section 2.3).
const SIG_KEY_GEN: &str = "0x74535e5be4948ecb1dd353a96d6bd21421f97f037fcde676fa71f1a472fae3a3";
const ENC_KEY_GEN: &str = "0x387134452cc97b763175d92d570f042b6fab62398f25cdcf515119c8e68320a0";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    mnemonic: String,
    passphrase: String,
    account: u32,
    path: String,
    /// The 64-byte BIP-39 seed.
    seed: String,
    account_public_key: String,
    encryption_public_key: String,
    /// `AccountKeys.toSecretKeyHex()`.
    secret_key_hex: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(VECTORS).unwrap()
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
    let all = [0, 1, MAX_ACCOUNT];
    let inputs: [(&str, &str, &[u32]); 4] = [
        (ABANDON_ABOUT, "", &all),
        (ABANDON_ABOUT, "TREZOR", &all),
        (LEGAL_WINNER_TITLE, "TREZOR", &all),
        (ABANDON_ABOUT, NFKD_PASSPHRASE, &[0]),
    ];
    let mut vectors = Vec::new();
    for (mnemonic, passphrase, accounts) in inputs {
        let master = from_mnemonic(mnemonic, passphrase);
        for &account in accounts {
            let keys = master.derive_account_keys(account as f64).unwrap();
            let (account_public_key, encryption_public_key) = public_keys_hex(&keys);
            vectors.push(Vector {
                mnemonic: mnemonic.to_string(),
                passphrase: passphrase.to_string(),
                account,
                path: path_for(account),
                seed: hex0x(spec::bip39_seed(mnemonic, passphrase).to_vec()),
                account_public_key,
                encryption_public_key,
                secret_key_hex: keys.to_secret_key_hex(),
            });
        }
    }
    // The generators of section 2.3.
    let gens = polymesh_dart::dart_gens();
    eprintln!("sig_key_gen {}", spec::compressed(&gens.sig_key_gen()));
    eprintln!("enc_key_gen {}", spec::compressed(&gens.enc_key_gen()));
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}

#[wasm_bindgen_test]
fn path_template_is_the_dart_bip44_path() {
    assert_eq!(DART_KEY_PATH_TEMPLATE, "m/44'/595'/{account}'/0/0");
}

#[wasm_bindgen_test]
fn mnemonic_vectors_match() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 10);
    for v in vectors {
        let what = format!(
            "{:?} / {:?} / account {}",
            v.mnemonic, v.passphrase, v.account
        );
        assert_eq!(v.path, path_for(v.account));
        let master = from_mnemonic(&v.mnemonic, &v.passphrase);
        let keys = master.derive_account_keys(v.account as f64).unwrap();
        assert_eq!(
            public_keys_hex(&keys),
            (
                v.account_public_key.clone(),
                v.encryption_public_key.clone()
            ),
            "{}",
            what
        );
        assert_eq!(keys.to_secret_key_hex(), v.secret_key_hex, "{}", what);
        // The secret key hex holds the same public keys (section 3.1), and imports.
        assert_eq!(
            &v.secret_key_hex[2..66],
            &v.encryption_public_key[2..],
            "{}",
            what
        );
        assert_eq!(
            &v.secret_key_hex[130..194],
            &v.account_public_key[2..],
            "{}",
            what
        );
        let imported = AccountKeys::from_secret_key_hex(v.secret_key_hex.clone()).unwrap();
        assert_eq!(imported.to_secret_key_hex(), v.secret_key_hex, "{}", what);
        // `seed` is the master seed: `fromBytes(seed)` gives the same keys.
        let seed = hex::decode(&v.seed[2..]).unwrap();
        assert_eq!(seed.len(), 64);
        let from_seed = MasterSeed::from_bytes(seed).unwrap();
        assert_eq!(
            from_seed
                .derive_account_keys(v.account as f64)
                .unwrap()
                .to_secret_key_hex(),
            v.secret_key_hex,
            "{}",
            what
        );
    }
}

/// The vectors' `seed` is the BIP-39 seed of the specification's section 2.1, computed here from
/// its text (NFKD, split on whitespace, words joined by one space, PBKDF2-HMAC-SHA512) rather
/// than with the `bip39` crate.
#[wasm_bindgen_test]
fn vector_seeds_follow_the_spec_bip39_construction() {
    for v in vectors() {
        assert_eq!(
            hex0x(spec::bip39_seed(&v.mnemonic, &v.passphrase).to_vec()),
            v.seed,
            "{:?} / {:?}",
            v.mnemonic,
            v.passphrase
        );
    }
    // The official BIP-39 seeds.
    assert_eq!(
        hex::encode(spec::bip39_seed(ABANDON_ABOUT, "TREZOR")),
        ABANDON_ABOUT_TREZOR_SEED
    );
    assert_eq!(
        hex::encode(spec::bip39_seed(LEGAL_WINNER_TITLE, "TREZOR")),
        LEGAL_WINNER_TITLE_TREZOR_SEED
    );
    // The NFKD vector's salt is "mnemonic" ‖ "cafe" U+0301 " fi", not its NFC bytes.
    let v = vectors()
        .into_iter()
        .find(|v| v.passphrase == NFKD_PASSPHRASE)
        .expect("the NFKD vector");
    let nfkd = spec::bip39_seed_raw_passphrase(ABANDON_ABOUT, "cafe\u{301} fi".as_bytes());
    let nfc = spec::bip39_seed_raw_passphrase(ABANDON_ABOUT, NFKD_PASSPHRASE.as_bytes());
    assert_eq!(hex0x(nfkd.to_vec()), v.seed);
    assert_ne!(nfc, nfkd);
    // And `fromMnemonic` normalises it: the NFKD spelling gives the same keys.
    assert_eq!(
        from_mnemonic(ABANDON_ABOUT, "cafe\u{301} fi")
            .derive_account_keys(0.0)
            .unwrap()
            .to_secret_key_hex(),
        v.secret_key_hex
    );
}

/// The vectors' secret scalars and public keys follow the specification's sections 2.2 and 2.3,
/// computed here from its text: IETF KeyGen with HKDF-SHA-256 over the seed, the exact salts and
/// `key_info`, reduced modulo the Pallas group order, then `sk · G` with the published generators.
#[wasm_bindgen_test]
fn vector_secrets_follow_the_spec_keygen_construction() {
    use ark_ec::{AffineRepr, CurveGroup};

    let sig_key_gen = spec::point(SIG_KEY_GEN);
    let enc_key_gen = spec::point(ENC_KEY_GEN);
    // The published generators are DART's.
    let gens = polymesh_dart::dart_gens();
    assert_eq!(sig_key_gen, gens.sig_key_gen());
    assert_eq!(enc_key_gen, gens.enc_key_gen());
    assert!(!sig_key_gen.is_zero() && !enc_key_gen.is_zero());

    for v in vectors() {
        let seed = hex::decode(&v.seed[2..]).unwrap();
        let sig_sk = spec::keygen(spec::SIG_KEY_SALT, &seed, &v.path);
        let enc_sk = spec::keygen(spec::ENC_KEY_SALT, &seed, &v.path);
        // Section 3.1: enc.public ‖ enc.secret ‖ acct.public ‖ acct.secret.
        assert_eq!(
            &v.secret_key_hex[66..130],
            &spec::compressed(&enc_sk)[2..],
            "{}",
            v.path
        );
        assert_eq!(
            &v.secret_key_hex[194..258],
            &spec::compressed(&sig_sk)[2..],
            "{}",
            v.path
        );

        let enc_pk = (enc_key_gen * enc_sk).into_affine();
        let sig_pk = (sig_key_gen * sig_sk).into_affine();
        assert_eq!(
            spec::compressed(&enc_pk),
            v.encryption_public_key,
            "{}",
            v.path
        );
        assert_eq!(
            spec::compressed(&sig_pk),
            v.account_public_key,
            "{}",
            v.path
        );
    }
}

/// The two spec-construction checks above, natively: `cargo test --release --test
/// wasm_keys_derivation`.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_vectors_follow_the_spec_construction() {
    vector_seeds_follow_the_spec_bip39_construction();
    vector_secrets_follow_the_spec_keygen_construction();
}

/// An independent implementation of the specification's section 2, for the tests above.
mod spec {
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use sha2::{Digest, Sha256, Sha512};
    use unicode_normalization::UnicodeNormalization;

    pub const SIG_KEY_SALT: &[u8] = b"POLYMESH-DART-V1-SIG-KEY";
    pub const ENC_KEY_SALT: &[u8] = b"POLYMESH-DART-V1-ENC-KEY";
    /// `ceil((3 * ceil(log2(r))) / 16)` for the 255-bit Pallas group order `r`.
    const L: usize = 48;

    /// `0x` + the hex of the arkworks compressed encoding.
    pub fn compressed<T: CanonicalSerialize>(value: &T) -> String {
        let mut out = Vec::new();
        value.serialize_compressed(&mut out).unwrap();
        format!("0x{}", hex::encode(out))
    }

    pub fn point(hex: &str) -> ark_pallas::Affine {
        ark_pallas::Affine::deserialize_compressed(&hex::decode(&hex[2..]).unwrap()[..]).unwrap()
    }

    /// Section 2.1, with the passphrase's salt bytes given directly.
    pub fn bip39_seed_raw_passphrase(mnemonic: &str, passphrase: &[u8]) -> [u8; 64] {
        let normalized: String = mnemonic.nfkd().collect();
        let password = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(passphrase);
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, 2048, &mut seed);
        seed
    }

    /// Section 2.1.
    pub fn bip39_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
        let passphrase: String = passphrase.nfkd().collect();
        bip39_seed_raw_passphrase(mnemonic, passphrase.as_bytes())
    }

    /// Section 2.2: KeyGen of draft-irtf-cfrg-bls-signature-05 section 2.3.
    pub fn keygen(salt: &[u8], ikm: &[u8], path: &str) -> ark_pallas::Fr {
        // key_info = u32le(len(path)) ‖ path ‖ u16le(0) ‖ 0x00
        let mut key_info = (path.len() as u32).to_le_bytes().to_vec();
        key_info.extend_from_slice(path.as_bytes());
        key_info.extend_from_slice(&0u16.to_le_bytes());
        key_info.push(0);
        // HKDF-Expand info = key_info ‖ I2OSP(L, 2)
        let mut info = key_info;
        info.extend_from_slice(&(L as u16).to_be_bytes());
        // HKDF-Extract input = IKM ‖ I2OSP(0, 1)
        let mut ikm0 = ikm.to_vec();
        ikm0.push(0);

        let mut salt = salt.to_vec();
        loop {
            let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm0);
            let mut okm = [0u8; L];
            hkdf.expand(&info, &mut okm).unwrap();
            let sk = ark_pallas::Fr::from_be_bytes_mod_order(&okm);
            if !sk.is_zero() {
                return sk;
            }
            salt = Sha256::digest(&salt).to_vec();
        }
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

/// `bytes` with `edit` applied, as secret key hex.
fn edited_secret_hex(hex: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut bytes = ::hex::decode(&hex[2..]).unwrap();
    edit(&mut bytes);
    format!("0x{}", ::hex::encode(bytes))
}

fn import_err(hex: String) -> String {
    AccountKeys::from_secret_key_hex(hex)
        .err()
        .expect("must be rejected")
        .as_string()
        .unwrap()
}

/// Section 3.2: an imported secret key must be consistent, whatever its source.
#[wasm_bindgen_test]
fn inconsistent_secret_key_hex_rejected() {
    let hex = from_mnemonic(ABANDON_ABOUT, "")
        .derive_account_keys(0.0)
        .unwrap()
        .to_secret_key_hex();
    const MISMATCH: &str = "Invalid secret key: the public keys don't match the secret keys";
    const BAD_POINT: &str = "Invalid secret key: a public key is not a valid Pallas point";
    const ZERO: &str = "Invalid secret key: a secret key is zero";

    // A flipped bit in the low byte of a secret: still a valid scalar, but another key.
    for at in [32, 96] {
        let flipped = edited_secret_hex(&hex, |b| b[at] ^= 0x01);
        assert_eq!(import_err(flipped), MISMATCH, "secret at {}", at);
    }
    // The secrets swapped between the two pairs.
    let swapped = edited_secret_hex(&hex, |b| {
        let enc: Vec<u8> = b[32..64].to_vec();
        let acct: Vec<u8> = b[96..128].to_vec();
        b[32..64].copy_from_slice(&acct);
        b[96..128].copy_from_slice(&enc);
    });
    assert_eq!(import_err(swapped), MISMATCH);
    // Another account's public key.
    let other = from_mnemonic(ABANDON_ABOUT, "")
        .derive_account_keys(1.0)
        .unwrap()
        .to_secret_key_hex();
    let other = ::hex::decode(&other[2..]).unwrap();
    let foreign = edited_secret_hex(&hex, |b| b[64..96].copy_from_slice(&other[64..96]));
    assert_eq!(import_err(foreign), MISMATCH);
    // A public key of all 0xff bytes isn't a point.
    for at in [0, 64] {
        let bad = edited_secret_hex(&hex, |b| b[at..at + 32].fill(0xff));
        assert_eq!(import_err(bad), BAD_POINT, "public at {}", at);
    }
    // A zero secret with the identity as its public key is consistent, but not a key.
    let mut identity = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(
        &<ark_pallas::Affine as ark_ec::AffineRepr>::zero(),
        &mut identity,
    )
    .unwrap();
    let zero = edited_secret_hex(&hex, |b| {
        b[64..96].copy_from_slice(&identity);
        b[96..128].fill(0);
    });
    assert_eq!(import_err(zero), ZERO);
    // The original still imports.
    assert!(AccountKeys::from_secret_key_hex(hex).is_ok());
}

/// Section 2.1 and 6.1: strings are encoded with the WHATWG UTF-8 encoder, as wasm-bindgen does,
/// so a lone surrogate becomes U+FFFD before anything else sees it.
#[wasm_bindgen_test]
fn lone_surrogate_passphrase_is_replacement_character() {
    let lone = js_sys::JsString::from_char_code1(0xd800);
    assert!(!lone.is_valid_utf16());
    let converted: String = JsValue::from(lone).as_string().unwrap();
    assert_eq!(converted, "\u{fffd}");
    let keys = |passphrase: String| {
        MasterSeed::from_mnemonic(ABANDON_ABOUT.to_string(), Some(passphrase))
            .unwrap()
            .derive_account_keys(0.0)
            .unwrap()
            .to_secret_key_hex()
    };
    assert_eq!(keys(converted), keys("\u{fffd}".to_string()));
}
