//! The encrypted DART key file, version 1 (`docs/KEY_FILE_FORMAT.md`), through the public API.
//!
//! The byte-for-byte reference vectors (`tests/vectors/key-file-v1.json`) are checked by the unit
//! tests in `src/key_file.rs`, which can encrypt with a fixed salt and nonce.

use base64::Engine as _;
use polymesh_dart_wasm::*;
use serde_json::{json, Value};
use wasm_bindgen_test::*;

/// A key file written by polkadot.js 13.5.9 `jsonEncrypt`, from
/// `node scripts/key-file-interop/interop.mjs --emit-fixture`.
const POLKADOT_JS_FIXTURE: &str = include_str!("vectors/key-file-v1-polkadot-js.json");

const ABANDON_ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const PASSWORD: &str = "correct horse battery staple";
const WRONG_PASSWORD: &str = "correct horse battery stapler";

const INVALID_PASSWORD: &str = "Invalid password or corrupted key file";
const UNSUPPORTED: &str = "Unsupported key file";
const PUBLIC_KEY_MISMATCH: &str = "Key file public keys don't match its encrypted keys";

fn keys(account: u32) -> AccountKeys {
    MasterSeed::from_mnemonic(ABANDON_ABOUT.to_string(), None)
        .unwrap()
        .derive_account_keys(account as f64)
        .unwrap()
}

fn hex0x(bytes: Vec<u8>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn encrypt(keys: &AccountKeys, path: Option<&str>) -> String {
    encrypt_key_file(
        keys,
        PASSWORD.to_string(),
        "Treasury".to_string(),
        path.map(str::to_string),
    )
    .unwrap()
}

fn decrypt_err(json: &str, password: &str) -> String {
    decrypt_key_file(json.to_string(), password.to_string())
        .err()
        .expect("the key file must be rejected")
        .as_string()
        .expect("errors are strings")
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Re-encodes `file.encoded` after `edit` changes its payload bytes.
fn edit_payload(file: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut value: Value = serde_json::from_str(file).unwrap();
    let mut payload = b64().decode(value["encoded"].as_str().unwrap()).unwrap();
    edit(&mut payload);
    value["encoded"] = Value::String(b64().encode(&payload));
    value.to_string()
}

fn edit_json(file: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(file).unwrap();
    edit(&mut value);
    value.to_string()
}

#[wasm_bindgen_test]
fn key_file_round_trip() {
    let keys = keys(0);
    let path = "m/44'/595'/0'/0/0";
    let file = encrypt(&keys, Some(path));

    let opened = decrypt_key_file(file.clone(), PASSWORD.to_string()).unwrap();
    assert_eq!(opened.name(), "Treasury");
    assert_eq!(opened.derivation_path().as_deref(), Some(path));
    assert_eq!(
        opened.account_keys().to_secret_key_hex(),
        keys.to_secret_key_hex()
    );

    // The written structure (section 5).
    let value: Value = serde_json::from_str(&file).unwrap();
    let public = keys.public_keys();
    assert_eq!(value["type"], "dart-key-file");
    assert_eq!(value["version"], 1);
    assert_eq!(
        value["public"],
        json!({
            "account": hex0x(public.account_public_key().to_bytes()),
            "encryption": hex0x(public.encryption_public_key().to_bytes()),
        })
    );
    assert_eq!(
        value["encoding"],
        json!({
            "content": ["dart-account-keys", "scale-v1"],
            "type": ["scrypt", "xsalsa20-poly1305"],
            "version": "3",
        })
    );
    assert_eq!(value["meta"]["derivationPath"], path);
    let created = value["meta"]["created"].as_u64().unwrap();
    assert!(created > 1_700_000_000_000, "meta.created is Date.now()");
    assert_eq!(opened.created(), created as f64);

    // The payload (section 6.4): 212 bytes, written with N = 2^17, p = 1, r = 8.
    let encoded = value["encoded"].as_str().unwrap();
    assert_eq!(encoded.len(), 284);
    let payload = b64().decode(encoded).unwrap();
    assert_eq!(payload.len(), 212);
    assert_eq!(&payload[32..44], &[0, 0, 2, 0, 1, 0, 0, 0, 8, 0, 0, 0][..]);

    // A fresh salt and nonce every time, even for the same keys and password.
    let again = encrypt(&keys, Some(path));
    let payload_again = b64()
        .decode(
            serde_json::from_str::<Value>(&again).unwrap()["encoded"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_ne!(payload[0..32], payload_again[0..32], "salt reused");
    assert_ne!(payload[44..68], payload_again[44..68], "nonce reused");
}

#[wasm_bindgen_test]
fn round_trip_without_derivation_path() {
    let keys = keys(1);
    let file = encrypt_key_file(&keys, "0x1234".to_string(), String::new(), None).unwrap();
    let value: Value = serde_json::from_str(&file).unwrap();
    assert_eq!(value["name"], "");
    assert!(value["meta"].get("derivationPath").is_none());

    let opened = decrypt_key_file(file.clone(), "0x1234".to_string()).unwrap();
    assert_eq!(opened.name(), "");
    assert_eq!(opened.derivation_path(), None);
    assert_eq!(
        opened.account_keys().to_secret_key_hex(),
        keys.to_secret_key_hex()
    );
    // The password is its UTF-8 bytes, not hex-decoded: the bytes 12 34 don't open it.
    assert_eq!(decrypt_err(&file, "\u{12}\u{34}"), INVALID_PASSWORD);
}

#[wasm_bindgen_test]
fn wrong_password_rejected() {
    let file = encrypt(&keys(0), None);
    assert_eq!(decrypt_err(&file, WRONG_PASSWORD), INVALID_PASSWORD);
    assert_eq!(decrypt_err(&file, ""), INVALID_PASSWORD);
}

#[wasm_bindgen_test]
fn tampered_ciphertext_rejected() {
    let file = encrypt(&keys(0), None);
    // The same message as a wrong password, whichever byte changed: the salt, the nonce, the tag
    // or the encrypted keys.
    for offset in [0, 50, 70, 100, 211] {
        let tampered = edit_payload(&file, |p| p[offset] ^= 0x01);
        assert_eq!(
            decrypt_err(&tampered, PASSWORD),
            INVALID_PASSWORD,
            "byte {}",
            offset
        );
    }
}

#[wasm_bindgen_test]
fn public_key_mismatch_rejected() {
    let file = encrypt(&keys(0), None);
    let other = keys(1).public_keys();
    let other_account = hex0x(other.account_public_key().to_bytes());
    let other_encryption = hex0x(other.encryption_public_key().to_bytes());

    let tampered = edit_json(&file, |v| v["public"]["account"] = json!(other_account));
    assert_eq!(decrypt_err(&tampered, PASSWORD), PUBLIC_KEY_MISMATCH);
    let tampered = edit_json(&file, |v| {
        v["public"]["encryption"] = json!(other_encryption)
    });
    assert_eq!(decrypt_err(&tampered, PASSWORD), PUBLIC_KEY_MISMATCH);
    // The two public keys swapped.
    let swapped = edit_json(&file, |v| {
        let account = v["public"]["account"].clone();
        v["public"]["account"] = v["public"]["encryption"].clone();
        v["public"]["encryption"] = account;
    });
    assert_eq!(decrypt_err(&swapped, PASSWORD), PUBLIC_KEY_MISMATCH);
}

#[wasm_bindgen_test]
fn unknown_version_rejected() {
    let file = encrypt(&keys(0), None);
    for version in [json!(2), json!(0), json!("1"), json!(null)] {
        let changed = edit_json(&file, |v| v["version"] = version.clone());
        assert_eq!(
            decrypt_err(&changed, PASSWORD),
            UNSUPPORTED,
            "version {}",
            version
        );
    }
    let missing = edit_json(&file, |v| {
        v.as_object_mut().unwrap().remove("version");
    });
    assert_eq!(decrypt_err(&missing, PASSWORD), UNSUPPORTED);
    for bad in [json!("2"), json!(3)] {
        let changed = edit_json(&file, |v| v["encoding"]["version"] = bad.clone());
        assert_eq!(decrypt_err(&changed, PASSWORD), UNSUPPORTED);
    }
    let unencrypted = edit_json(&file, |v| v["encoding"]["type"] = json!(["none"]));
    assert_eq!(decrypt_err(&unencrypted, PASSWORD), UNSUPPORTED);
    let other_type = edit_json(&file, |v| v["type"] = json!("polkadot-account"));
    assert_eq!(decrypt_err(&other_type, PASSWORD), UNSUPPORTED);
    // Checked before the payload: an unsupported version with a broken payload is unsupported.
    let both = edit_json(&file, |v| {
        v["version"] = json!(2);
        v["encoded"] = json!("not base64");
    });
    assert_eq!(decrypt_err(&both, PASSWORD), UNSUPPORTED);
}

#[wasm_bindgen_test]
fn mnemonic_content_rejected_in_v1() {
    let file = encrypt(&keys(0), None);
    for content in [
        json!(["dart-mnemonic", "bip39-v1"]),
        json!(["dart-mnemonic"]),
        json!(["dart-account-keys"]),
        json!(["scale-v1", "dart-account-keys"]),
    ] {
        let changed = edit_json(&file, |v| v["encoding"]["content"] = content.clone());
        assert_eq!(
            decrypt_err(&changed, PASSWORD),
            UNSUPPORTED,
            "content {}",
            content
        );
    }
}

#[wasm_bindgen_test]
fn unsupported_scrypt_params_rejected_before_scrypt() {
    let file = encrypt(&keys(0), None);
    // N = 2^20 would need 1 GiB: it is refused from the header, without running scrypt.
    for (n, p, r) in [
        (1u32 << 20, 1u32, 8u32),
        (1 << 14, 5, 8),
        (1 << 13, 10, 8),
        (1 << 17, 1, 16),
    ] {
        let changed = edit_payload(&file, |payload| {
            payload[32..36].copy_from_slice(&n.to_le_bytes());
            payload[36..40].copy_from_slice(&p.to_le_bytes());
            payload[40..44].copy_from_slice(&r.to_le_bytes());
        });
        assert_eq!(
            decrypt_err(&changed, PASSWORD),
            UNSUPPORTED,
            "N={} p={} r={}",
            n,
            p,
            r
        );
    }
}

#[wasm_bindgen_test]
fn malformed_files_rejected() {
    let file = encrypt(&keys(0), Some("m/44'/595'/0'/0/0"));
    let cases: Vec<(&str, String)> = vec![
        ("not JSON", "not json".to_string()),
        ("not an object", "[]".to_string()),
        (
            "missing name",
            edit_json(&file, |v| {
                v.as_object_mut().unwrap().remove("name");
            }),
        ),
        (
            "name not a string",
            edit_json(&file, |v| v["name"] = json!(1)),
        ),
        (
            "unknown member",
            edit_json(&file, |v| v["extra"] = json!(true)),
        ),
        (
            "upper-case hex",
            edit_json(&file, |v| {
                let upper = v["public"]["account"]
                    .as_str()
                    .unwrap()
                    .to_uppercase()
                    .replace("0X", "0x");
                v["public"]["account"] = json!(upper);
            }),
        ),
        (
            "unknown public member",
            edit_json(&file, |v| v["public"]["extra"] = json!("0x00")),
        ),
        (
            "unknown encoding member",
            edit_json(&file, |v| v["encoding"]["extra"] = json!(1)),
        ),
        (
            "meta not an object",
            edit_json(&file, |v| v["meta"] = json!([])),
        ),
        (
            "created missing",
            edit_json(&file, |v| {
                v["meta"].as_object_mut().unwrap().remove("created");
            }),
        ),
        (
            "created negative",
            edit_json(&file, |v| v["meta"]["created"] = json!(-1)),
        ),
        (
            "created fractional",
            edit_json(&file, |v| v["meta"]["created"] = json!(1.5)),
        ),
        (
            "created above 2^53 - 1",
            edit_json(&file, |v| v["meta"]["created"] = json!(9007199254740992u64)),
        ),
        (
            "account index out of range",
            edit_json(&file, |v| {
                v["meta"]["derivationPath"] = json!("m/44'/595'/2147483648'/0/0")
            }),
        ),
        (
            "leading zero",
            edit_json(&file, |v| {
                v["meta"]["derivationPath"] = json!("m/44'/595'/01'/0/0")
            }),
        ),
        (
            "not hardened",
            edit_json(&file, |v| {
                v["meta"]["derivationPath"] = json!("m/44'/595'/0/0/0")
            }),
        ),
        (
            "derivationPath not a string",
            edit_json(&file, |v| v["meta"]["derivationPath"] = json!(0)),
        ),
        (
            "encoded not base64",
            edit_json(&file, |v| v["encoded"] = json!("@@@@")),
        ),
        (
            "encoded with a line break",
            edit_json(&file, |v| {
                let encoded = v["encoded"].as_str().unwrap();
                v["encoded"] = json!(format!("{}\n{}", &encoded[..76], &encoded[76..]));
            }),
        ),
        (
            "encoded without padding",
            edit_json(&file, |v| {
                let encoded = v["encoded"]
                    .as_str()
                    .unwrap()
                    .trim_end_matches('=')
                    .to_string();
                v["encoded"] = json!(encoded);
            }),
        ),
        (
            "encoded too short",
            edit_payload(&file, |p| p.truncate(211)),
        ),
        ("encoded too long", edit_payload(&file, |p| p.push(0))),
    ];
    for (what, json) in cases {
        let err = decrypt_err(&json, PASSWORD);
        assert!(err.starts_with("Invalid key file"), "{}: {}", what, err);
    }
}

/// `DecryptedKeyFile.created()` is `meta.created`, exactly, across the whole range.
#[wasm_bindgen_test]
fn created_is_meta_created() {
    let file = encrypt(&keys(0), None);
    for created in [0u64, 1764201600000, (1 << 53) - 1] {
        let changed = edit_json(&file, |v| v["meta"]["created"] = json!(created));
        let opened = decrypt_key_file(changed, PASSWORD.to_string()).unwrap();
        assert_eq!(opened.created(), created as f64, "created {}", created);
    }
    // `1.0` is the same number as `1`.
    let float = edit_json(&file, |v| v["meta"]["created"] = json!(1.0));
    assert_eq!(
        decrypt_key_file(float, PASSWORD.to_string())
            .unwrap()
            .created(),
        1.0
    );
}

/// The plaintext's public keys must match its secret keys (section 3.2, step 9), even when the
/// clear-text `public` member matches the plaintext.
#[wasm_bindgen_test]
fn inconsistent_plaintext_rejected() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/key-file-v1.json")).unwrap();
    let inconsistent: Vec<&Value> = vectors["invalid"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["step"] == 9 && v["description"].as_str().unwrap().contains("flipped bit"))
        .collect();
    assert_eq!(inconsistent.len(), 2);
    for v in inconsistent {
        let err = decrypt_err(v["file"].as_str().unwrap(), v["password"].as_str().unwrap());
        assert!(
            err.starts_with("Corrupted key file"),
            "{}: {}",
            v["description"],
            err
        );
    }
}

#[wasm_bindgen_test]
fn unknown_meta_members_ignored() {
    let keys = keys(0);
    let file = edit_json(&encrypt(&keys, None), |v| {
        v["meta"]["app"] = json!({ "colour": "red" })
    });
    let opened = decrypt_key_file(file, PASSWORD.to_string()).unwrap();
    assert_eq!(
        opened.account_keys().to_secret_key_hex(),
        keys.to_secret_key_hex()
    );
}

#[wasm_bindgen_test]
fn writer_validates_its_inputs() {
    let keys = keys(0);
    let err = |password: &str, path: Option<&str>| {
        encrypt_key_file(
            &keys,
            password.to_string(),
            "n".to_string(),
            path.map(str::to_string),
        )
        .err()
        .expect("must be refused")
        .as_string()
        .unwrap()
    };
    assert!(err("", None).contains("password"));
    for bad in [
        "m/44'/595'/2147483648'/0/0",
        "m/44'/595'/01'/0/0",
        "m/44'/595'/-1'/0/0",
        "m/44'/595'/'/0/0",
        "m/44'/595'/0'/0/1",
        "m/44'/60'/0'/0/0",
        " m/44'/595'/0'/0/0",
        "",
    ] {
        assert!(
            err(PASSWORD, Some(bad)).contains("derivation path"),
            "{:?}",
            bad
        );
    }
    // The extremes of the range are accepted.
    let max = encrypt(&keys, Some("m/44'/595'/2147483647'/0/0"));
    let opened = decrypt_key_file(max, PASSWORD.to_string()).unwrap();
    assert_eq!(
        opened.derivation_path().as_deref(),
        Some("m/44'/595'/2147483647'/0/0")
    );
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolkadotFixture {
    password: String,
    secret_key_hex: String,
    file: Value,
}

#[wasm_bindgen_test]
fn polkadot_js_fixture_opens() {
    let fixture: PolkadotFixture = serde_json::from_str(POLKADOT_JS_FIXTURE).unwrap();
    let opened = decrypt_key_file(fixture.file.to_string(), fixture.password.clone()).unwrap();
    assert_eq!(
        opened.account_keys().to_secret_key_hex(),
        fixture.secret_key_hex
    );
    assert_eq!(
        Some(opened.name()),
        fixture.file["name"].as_str().map(str::to_string)
    );
    assert_eq!(
        decrypt_err(&fixture.file.to_string(), WRONG_PASSWORD),
        INVALID_PASSWORD
    );
}

/// The writer's output has the structure `schemas/dart-key-file-v1.schema.json` requires. (The
/// interop script validates files against the schema itself, with ajv.)
#[wasm_bindgen_test]
fn schema_valid() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/dart-key-file-v1.schema.json")).unwrap();
    let file: Value = serde_json::from_str(&encrypt(&keys(2), Some("m/44'/595'/2'/0/0"))).unwrap();
    let object = file.as_object().unwrap();

    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut members: Vec<&str> = object.keys().map(String::as_str).collect();
    members.sort();
    let mut expected = required.clone();
    expected.sort();
    assert_eq!(members, expected, "exactly the required members");

    let properties = &schema["properties"];
    assert_eq!(file["type"], properties["type"]["const"]);
    assert_eq!(file["version"], properties["version"]["const"]);
    for member in ["content", "type", "version"] {
        assert_eq!(
            file["encoding"][member],
            properties["encoding"]["properties"][member]["const"]
        );
    }
    let is_hex32 = |v: &Value| {
        let s = v.as_str().unwrap();
        s.len() == 66
            && s.starts_with("0x")
            && s[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    assert_eq!(file["public"].as_object().unwrap().len(), 2);
    assert!(is_hex32(&file["public"]["account"]));
    assert!(is_hex32(&file["public"]["encryption"]));

    // `^[A-Za-z0-9+/]{282}[AEIMQUYcgkosw048]=$`
    let encoded = file["encoded"].as_str().unwrap().as_bytes();
    assert_eq!(encoded.len(), 284);
    assert!(encoded[..282]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'));
    assert!(b"AEIMQUYcgkosw048".contains(&encoded[282]));
    assert_eq!(encoded[283], b'=');

    assert!(file["meta"]["created"].is_u64());
    assert_eq!(file["meta"]["derivationPath"], "m/44'/595'/2'/0/0");
}
